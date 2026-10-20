// Shared authentication and storage for the app, popup and transport document.
import { validateBundle,decodeEnrollment } from './profile-codec.js';
const browserAPI=globalThis.browser??globalThis.chrome;
const extension=!!browserAPI?.runtime?.id;
const encoder=new TextEncoder();
const STORE='knock-control-browser-v3';
const toHex=bytes=>[...bytes].map(n=>n.toString(16).padStart(2,'0')).join('');
const concat=(...arrays)=>{const result=new Uint8Array(arrays.reduce((sum,a)=>sum+a.length,0));let i=0;for(const a of arrays){result.set(a,i);i+=a.length;}return result;};
export function base32(secret) {
  let value=0,bits=0;const out=[];
  for(const c of secret){const n='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(c);if(n<0)throw new Error('Invalid secret');value=(value<<5)|n;bits+=5;if(bits>=8){bits-=8;out.push((value>>>bits)&255);}}
  return new Uint8Array(out);
}
async function hmac(secret,message,hash='SHA-256') {
  const key=await crypto.subtle.importKey('raw',base32(secret),{name:'HMAC',hash},false,['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC',key,message));
}
function counter(step) {const result=new Uint8Array(8),view=new DataView(result.buffer);view.setUint32(0,Math.floor(step/4294967296));view.setUint32(4,step>>>0);return result;}
export async function totp(secret,now=Date.now()/1000) {
  const digest=await hmac(secret,counter(Math.floor(now/30)),'SHA-1'),offset=digest[19]&15;
  const number=((digest[offset]&127)*16777216+digest[offset+1]*65536+digest[offset+2]*256+digest[offset+3])%1000000;
  return String(number).padStart(6,'0');
}
export async function makeProof(bundle,action,source,code='',now=Date.now()/1000,nonce=crypto.getRandomValues(new Uint8Array(16))) {
  let step=Math.floor(now/30);
  if(code){if(!/^[0-9]{6}$/.test(code))throw new Error('Enter the 6-digit Authenticator code');let match;
    for(const candidate of [step,step-1,step+1])if(await totp(bundle.secret,candidate*30)===code){match=candidate;break;}
    if(match===undefined)throw new Error('The Authenticator code is invalid or expired');step=match;
  } else code=await totp(bundle.secret,now);
  const door=bundle.profile_id+'.'+action,ip=bundle.settings.ip_protection?source:'-';
  const digest=new Uint8Array(await crypto.subtle.digest('SHA-256',encoder.encode(`knock-control:v1:${door}:${ip}:${code}`)));
  const sequence=bundle.settings.protocols.map((p,i)=>[bundle.settings.base+digest[i],p]);
  const stamp=counter(step),message=concat(encoder.encode('knock-control:confirm:v1:'),stamp,nonce,encoder.encode(door+':'+ip));
  const signature=await hmac(bundle.secret,message);
  const proof=concat(encoder.encode('KNC1'),stamp,nonce,signature);
  return {sequence,confirmation:btoa(String.fromCharCode(...proof))};
}
export async function apiSignature(secret,timestamp,nonce,body) {
  const digest=toHex(new Uint8Array(await crypto.subtle.digest('SHA-256',encoder.encode(body))));
  return toHex(await hmac(secret,encoder.encode(`knock-control:api:v2:POST:/v1/control:${timestamp}:${nonce}:${digest}`)));
}
export async function makeIceToken(bundle,action,source,now=Date.now(),nonce=crypto.getRandomValues(new Uint8Array(16)),issued=now) {
  if(!['open','close'].includes(action)||typeof source!=='string'||!/^\d{1,3}(\.\d{1,3}){3}$/.test(source)||source.split('.').some(n=>Number(n)>255)||!(nonce instanceof Uint8Array)||nonce.length!==16)throw new Error('Invalid ICE request');
  const hex=(n,size)=>BigInt(n).toString(16).padStart(size,'0');
  const prefix='KNI1'+bundle.profile_id+(action==='open'?'O':'C')+hex(bundle.revision,8)+hex(Math.floor(now/30000),16)+hex(Math.floor(issued),16)+toHex(nonce);
  return prefix+toHex(await hmac(bundle.secret,encoder.encode('knock-control:ice:v1:'+prefix+':'+(bundle.settings.ip_protection?source:'-'))));
}
async function remote(bundle,action,fields={}) {
  if(!extension&&bundle.server_url!==location.origin)throw new Error('Open the web app for this profile: '+bundle.server_url+'/app/');
  const body=JSON.stringify({action,...fields}),timestamp=String(Math.floor(Date.now()/1000)),nonce=toHex(crypto.getRandomValues(new Uint8Array(16)));
  const signature=await apiSignature(bundle.secret,timestamp,nonce,body);
  const abort=new AbortController(),timeout=setTimeout(()=>abort.abort(),15000);
  try {
    const response=await fetch(bundle.server_url+'/v1/control',{method:'POST',mode:'cors',redirect:'error',credentials:'omit',cache:'no-store',
      headers:{'Content-Type':'application/json',Authorization:`Knock ${bundle.profile_id}:${timestamp}:${nonce}:${signature}`},body,signal:abort.signal});
    if(Number(response.headers.get('Content-Length'))>65536)throw new Error('The server response is too large');
    const text=await response.text();if(text.length>65536)throw new Error('The server response is too large');
    const value=JSON.parse(text);
    if(!response.ok||!value.ok)throw new Error(value.error??'The server rejected the request');
    if(value.profile_id!==bundle.profile_id)throw new Error('The response belongs to another profile');
    return value;
  } catch(error) {
    if(error instanceof TypeError)throw new Error('Cannot connect securely. Check the network, HTTPS certificate and browser permission.');
    throw error;
  } finally {clearTimeout(timeout);}
}
async function readStore() {
  let value;
  if(extension)value=(await browserAPI.storage.local.get(STORE))[STORE];
  else {const text=localStorage.getItem(STORE);if(text)value=JSON.parse(text);}
  if(!value)return {version:3,active:null,profiles:{}};
  if(value.version!==3||!value.profiles)throw new Error('The local profile store is corrupted');
  return value;
}
async function writeStore(value) {
  if(extension)await browserAPI.storage.local.set({[STORE]:value});
  else localStorage.setItem(STORE,JSON.stringify(value));
}
const safe=bundle=>{const {secret,...result}=bundle;return result;};
async function keyFor(bundle){return toHex(new Uint8Array(await crypto.subtle.digest('SHA-256',encoder.encode(bundle.server_url+':'+bundle.profile_id)))).slice(0,32);}
function merge(bundle,response) {const value=validateBundle({...bundle,settings:response.settings,revision:response.revision});value.public_ip=response.observed_ip??bundle.public_ip;return value;}
export async function dispatch(message) {
  if(!message||typeof message!=='object')throw new Error('Invalid request');
  const store=await readStore(),action=message.action;
  if(action==='load'){
    const active=message.key??store.active;
    if(active&&!store.profiles[active])throw new Error('Unknown profile');
    return {ok:true,active,profile:active?safe(validateBundle(store.profiles[active])):null,
    profiles:Object.entries(store.profiles).map(([key,value])=>({key,name:value.name,server_url:value.server_url}))};
  }
  if(action==='import') {
    const bundle=typeof message.bundle==='string'?decodeEnrollment(message.bundle):validateBundle(message.bundle);
    if(!extension&&bundle.server_url!==location.origin)throw new Error('This profile belongs to another server. Open '+bundle.server_url+'/app/');
    const key=await keyFor(bundle);store.profiles[key]=bundle;store.active=key;await writeStore(store);
    return {ok:true,profile:safe(bundle)};
  }
  if(action==='select') {if(!store.profiles[message.key])throw new Error('Unknown profile');store.active=message.key;await writeStore(store);return {ok:true};}
  const selected=action==='ice-proof'&&message.key?message.key:store.active;
  let bundle=selected&&store.profiles[selected]?validateBundle(store.profiles[selected]):null;
  if(!bundle)throw new Error('Import the server-issued QR profile first');
  if(action==='pairing')return {ok:true,secret:bundle.secret,uri:'otpauth://totp/'+encodeURIComponent('Knock Control:'+bundle.name)+'?'+new URLSearchParams({secret:bundle.secret,issuer:'Knock Control',algorithm:'SHA1',digits:'6',period:'30'})};
  if(action==='save-transport') {
    if(!message.connection||typeof message.connection!=='object'||Object.keys(message.connection).some(k=>!['transport','ice_source','ice_host','stun_server'].includes(k)))throw new Error('Invalid connection settings');
    bundle=validateBundle({...bundle,...message.connection});store.profiles[store.active]=bundle;await writeStore(store);return {ok:true,profile:safe(bundle)};
  }
  if(action==='ice-proof') {
    const now=Date.now(),issued=Math.max(now,(bundle.last_ice_ms??0)+1);
    if(message.code){let valid=false;for(const step of [Math.floor(now/30000),Math.floor(now/30000)-1,Math.floor(now/30000)+1])if(await totp(bundle.secret,step*30)===message.code)valid=true;if(!valid)throw new Error('The Authenticator code is invalid or expired');}
    const token=await makeIceToken(bundle,message.operation,message.source,now,crypto.getRandomValues(new Uint8Array(16)),issued);
    bundle.last_ice_ms=issued;store.profiles[selected]=bundle;await writeStore(store);
    return {ok:true,token,host:bundle.ice_host||bundle.knock_host,port:bundle.settings.base,profile:safe(bundle)};
  }
  if(action==='save')return {ok:true};
  if(!['status','configure','open','close'].includes(action))throw new Error('Unknown operation');
  let response=await remote(bundle,'status');bundle=merge(bundle,response);
  if(action==='configure')response=await remote(bundle,'configure',{settings:message.settings,revision:bundle.revision});
  if(action==='open'||action==='close') {
    if(response.policy.allow_browser_transport===false)throw new Error('The administrator only allows the TCP/UDP client for this profile');
    const proof=await makeProof(bundle,action,response.observed_ip,message.code??'');
    response=await remote(bundle,'browser-'+action,proof);
  }
  bundle=merge(bundle,response);store.profiles[store.active]=bundle;await writeStore(store);
  return {...response,profile:safe(bundle)};
}
let queue=Promise.resolve();
export function queuedDispatch(message) {
  const run=()=>dispatch(message);
  if(!extension&&navigator.locks)return navigator.locks.request('knock-control-store',run);
  const result=queue.then(run,run);queue=result.catch(()=>{});return result;
}

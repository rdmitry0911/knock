// Shared authentication and storage for the app, popup and transport document.
import { validateBundle,decodeEnrollment } from './profile-codec.js';
const browserAPI=globalThis.browser??globalThis.chrome;
const extension=!!browserAPI?.runtime?.id;
const encoder=new TextEncoder();
const STORE='knock-control-browser-v3';
const toHex=bytes=>[...bytes].map(n=>n.toString(16).padStart(2,'0')).join('');
export function base32(secret) {
  let value=0,bits=0;const out=[];
  for(const c of secret){const n='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(c);if(n<0)throw new Error('Invalid secret');value=(value<<5)|n;bits+=5;if(bits>=8){bits-=8;out.push((value>>>bits)&255);}}
  return new Uint8Array(out);
}
async function hmac(secret,message,hash='SHA-256') {
  const key=await crypto.subtle.importKey('raw',base32(secret),{name:'HMAC',hash},false,['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC',key,message));
}
export async function makeIceToken(bundle,action,source,now=Date.now(),nonce=crypto.getRandomValues(new Uint8Array(16)),issued=now) {
  if(!['open','close'].includes(action)||typeof source!=='string'||!/^\d{1,3}(\.\d{1,3}){3}$/.test(source)||source.split('.').some(n=>Number(n)>255)||!(nonce instanceof Uint8Array)||nonce.length!==16)throw new Error('Invalid ICE request');
  const hex=(n,size)=>BigInt(n).toString(16).padStart(size,'0');
  const prefix='KNI1'+bundle.profile_id+(action==='open'?'O':'C')+hex(bundle.revision,8)+hex(Math.floor(now/30000),16)+hex(Math.floor(issued),16)+toHex(nonce);
  return prefix+toHex(await hmac(bundle.secret,encoder.encode('knock-control:ice:v1:'+prefix+':'+(bundle.settings.ip_protection?source:'-'))));
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
async function keyFor(bundle){return toHex(new Uint8Array(await crypto.subtle.digest('SHA-256',encoder.encode(bundle.knock_host+':'+bundle.profile_id)))).slice(0,32);}
export async function dispatch(message) {
  if(!message||typeof message!=='object')throw new Error('Invalid request');
  const store=await readStore(),action=message.action;
  if(action==='load'){
    const active=message.key??store.active;
    if(active&&!store.profiles[active])throw new Error('Unknown profile');
    return {ok:true,active,profile:active?safe(validateBundle(store.profiles[active])):null,
    profiles:Object.entries(store.profiles).map(([key,value])=>({key,name:value.name,knock_host:value.knock_host}))};
  }
  if(action==='import') {
    const bundle=typeof message.bundle==='string'?decodeEnrollment(message.bundle):validateBundle(message.bundle);
    const key=Object.keys(store.profiles).find(key=>{const old=store.profiles[key];return old.profile_id===bundle.profile_id&&old.knock_host===bundle.knock_host;})??await keyFor(bundle);store.profiles[key]=bundle;store.active=key;await writeStore(store);
    return {ok:true,profile:safe(bundle)};
  }
  if(action==='select') {if(!store.profiles[message.key])throw new Error('Unknown profile');store.active=message.key;await writeStore(store);return {ok:true};}
  if(action==='remove') {
    if(typeof message.key!=='string'||!store.profiles[message.key])throw new Error('Unknown profile');
    delete store.profiles[message.key];
    if(store.active===message.key)store.active=Object.keys(store.profiles)[0]??null;
    await writeStore(store);return {ok:true};
  }
  if(action!=='ice-proof')throw new Error('Unknown operation');
  const selected=message.key??store.active;
  const bundle=selected&&store.profiles[selected]?validateBundle(store.profiles[selected]):null;
  if(!bundle)throw new Error('Import a server-issued profile first');
  const now=Date.now(),issued=Math.max(now,(bundle.last_ice_ms??0)+1);
  const token=await makeIceToken(bundle,message.operation,message.source,now,crypto.getRandomValues(new Uint8Array(16)),issued);
  bundle.last_ice_ms=issued;store.profiles[selected]=bundle;await writeStore(store);
  return {ok:true,token,host:bundle.ice_host||bundle.knock_host,port:bundle.settings.base,profile:safe(bundle)};
}
let queue=Promise.resolve();
export function queuedDispatch(message) {
  const run=()=>dispatch(message);
  if(!extension&&navigator.locks)return navigator.locks.request('knock-control-store',run);
  const result=queue.then(run,run);queue=result.catch(()=>{});return result;
}

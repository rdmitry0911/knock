// Browser-only transport: Web Crypto + HTTPS. No native host or raw sockets.
import { validateBundle,decodeEnrollment } from './profile-codec.js';
const browserAPI=globalThis.browser??globalThis.chrome;
const extension=!!browserAPI?.runtime?.id;
const encoder=new TextEncoder();
const STORE='knock-control-browser-v3';
const toHex=bytes=>[...bytes].map(n=>n.toString(16).padStart(2,'0')).join('');
const concat=(...arrays)=>{const result=new Uint8Array(arrays.reduce((sum,a)=>sum+a.length,0));let i=0;for(const a of arrays){result.set(a,i);i+=a.length;}return result;};
export function base32(secret) {
  let value=0,bits=0;const out=[];
  for(const c of secret){const n='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(c);if(n<0)throw new Error('Некорректный ключ');value=(value<<5)|n;bits+=5;if(bits>=8){bits-=8;out.push((value>>>bits)&255);}}
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
  if(code){if(!/^[0-9]{6}$/.test(code))throw new Error('Введите 6 цифр из Authenticator');let match;
    for(const candidate of [step,step-1,step+1])if(await totp(bundle.secret,candidate*30)===code){match=candidate;break;}
    if(match===undefined)throw new Error('Код Authenticator неверен или истёк');step=match;
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
async function remote(bundle,action,fields={}) {
  if(!extension&&bundle.server_url!==location.origin)throw new Error('Откройте веб-приложение на сервере этого профиля: '+bundle.server_url+'/app/');
  const body=JSON.stringify({action,...fields}),timestamp=String(Math.floor(Date.now()/1000)),nonce=toHex(crypto.getRandomValues(new Uint8Array(16)));
  const signature=await apiSignature(bundle.secret,timestamp,nonce,body);
  const abort=new AbortController(),timeout=setTimeout(()=>abort.abort(),15000);
  try {
    const response=await fetch(bundle.server_url+'/v1/control',{method:'POST',mode:'cors',redirect:'error',credentials:'omit',cache:'no-store',
      headers:{'Content-Type':'application/json',Authorization:`Knock ${bundle.profile_id}:${timestamp}:${nonce}:${signature}`},body,signal:abort.signal});
    if(Number(response.headers.get('Content-Length'))>65536)throw new Error('Ответ сервера слишком большой');
    const text=await response.text();if(text.length>65536)throw new Error('Ответ сервера слишком большой');
    const value=JSON.parse(text);
    if(!response.ok||!value.ok)throw new Error(value.error??'Сервер отклонил запрос');
    if(value.profile_id!==bundle.profile_id)throw new Error('Ответ для другого профиля');
    return value;
  } catch(error) {
    if(error instanceof TypeError)throw new Error('Нет защищённого соединения с сервером. Проверьте сеть, HTTPS-сертификат и разрешение браузера.');
    throw error;
  } finally {clearTimeout(timeout);}
}
async function readStore() {
  let value;
  if(extension)value=(await browserAPI.storage.local.get(STORE))[STORE];
  else {const text=localStorage.getItem(STORE);if(text)value=JSON.parse(text);}
  if(!value)return {version:3,active:null,profiles:{}};
  if(value.version!==3||!value.profiles)throw new Error('Повреждено локальное хранилище профилей');
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
  if(!message||typeof message!=='object')throw new Error('Некорректный запрос');
  const store=await readStore(),action=message.action;
  if(action==='load')return {ok:true,active:store.active,profile:store.active?safe(validateBundle(store.profiles[store.active])):null,
    profiles:Object.entries(store.profiles).map(([key,value])=>({key,name:value.name,server_url:value.server_url}))};
  if(action==='import') {
    const bundle=typeof message.bundle==='string'?decodeEnrollment(message.bundle):validateBundle(message.bundle);
    if(!extension&&bundle.server_url!==location.origin)throw new Error('Этот профиль относится к другому серверу. Откройте '+bundle.server_url+'/app/');
    const key=await keyFor(bundle);store.profiles[key]=bundle;store.active=key;await writeStore(store);
    return {ok:true,profile:safe(bundle)};
  }
  if(action==='select') {if(!store.profiles[message.key])throw new Error('Неизвестный профиль');store.active=message.key;await writeStore(store);return {ok:true};}
  let bundle=store.active?validateBundle(store.profiles[store.active]):null;
  if(!bundle)throw new Error('Сначала импортируйте выданный сервером QR');
  if(action==='pairing')return {ok:true,secret:bundle.secret,uri:'otpauth://totp/'+encodeURIComponent('Knock Control:'+bundle.name)+'?'+new URLSearchParams({secret:bundle.secret,issuer:'Knock Control',algorithm:'SHA1',digits:'6',period:'30'})};
  if(action==='save')return {ok:true}; // API observes the authoritative source IPv4 automatically.
  if(!['status','configure','open','close'].includes(action))throw new Error('Неизвестная операция');
  let response=await remote(bundle,'status');bundle=merge(bundle,response);
  if(action==='configure')response=await remote(bundle,'configure',{settings:message.settings,revision:bundle.revision});
  if(action==='open'||action==='close') {
    if(response.policy.allow_browser_transport===false)throw new Error('Администратор разрешил этому профилю только TCP/UDP-клиент');
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

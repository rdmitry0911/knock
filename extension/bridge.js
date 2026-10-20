import { MODE } from './transport-config.js';
export const api=globalThis.browser??globalThis.chrome;
export const browserMode=MODE==='browser'||!api?.runtime?.id;
export const iceMode=profile=>browserMode&&(profile?.transport??(profile?.ice_version===1?'ice':'https'))==='ice';
export async function request(action,fields={}) {
  if(browserMode&&['open','close'].includes(action)) {
    const loaded=await request('load');
    if(iceMode(loaded.profile)) {
      const profile=loaded.profile,{sendIce,ipv4}=await import('./ice-client.js');
      const host=profile.ice_host||profile.knock_host;
      if(!ipv4(host))throw new Error('Для ICE укажите IPv4 knock-сервера в настройках подключения.');
      let proof;
      const sign=async source=>{proof=await request('ice-proof',{operation:action,source,code:fields.code});return proof.token;};
      const automatic=profile.settings.ip_protection&&!profile.ice_source;
      const token=automatic?sign:await sign(profile.ice_source||'0.0.0.0');
      await sendIce(host,profile.settings.base,token,4500,automatic?(profile.stun_server??'stun:stun.cloudflare.com:3478'):undefined);
      return {ok:true,profile:proof.profile,transport:'ice',message:'Подписанный UDP-knock '+(action==='open'?'ON':'OFF')+' отправлен. Ответ сервера не запрашивался.'};
    }
  }
  const message={action,...fields};let response;
  if(!api?.runtime?.id) {
    const {queuedDispatch}=await import('./browser-client.js');
    response=await queuedDispatch(message);
  } else if(browserMode) {
    response=await api.runtime.sendMessage(message);
  } else if(globalThis.browser)response=await browser.runtime.sendNativeMessage('org.knock.control',message);
  else response=await new Promise((resolve,reject)=>chrome.runtime.sendNativeMessage('org.knock.control',message,value=>{
    if(chrome.runtime.lastError)reject(new Error(chrome.runtime.lastError.message));else resolve(value);
  }));
  if(!response?.ok)throw new Error(response?.error??'Помощник не ответил');
  return response;
}
export async function ensurePermission(profile,action='status') {
  if(['open','close'].includes(action)&&iceMode(profile))return;
  if(!browserMode||!api?.permissions||!profile)return;
  const origin=new URL(profile.server_url).origin;
  // Match patterns use host scope (ports are deliberately not part of a pattern).
  const pattern='https://'+new URL(origin).hostname+'/*';
  // Called directly from ON/configure user gestures. Request is idempotent.
  const allowed=await api.permissions.request({origins:[pattern]});
  if(!allowed)throw new Error('Для подключения разрешите доступ к серверу '+origin);
}
export function showError(error) {
  document.querySelector('#message').textContent=error.message+(browserMode?'':'\nЕсли помощник недоступен, установите его по инструкции README_RU.md.');
}
export async function busy(work) {
  const buttons=[...document.querySelectorAll('button')];buttons.forEach(button=>{button.disabled=true;});
  try {await work();}catch(error){showError(error);}finally{buttons.forEach(button=>{button.disabled=false;});}
}

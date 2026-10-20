import {t} from './i18n.js';
export const api=globalThis.browser??globalThis.chrome;
export const browserMode=true;
export const iceMode=profile=>(profile?.transport??(profile?.ice_version===1?'ice':'https'))==='ice';
export async function request(action,fields={}) {
  if(['open','close'].includes(action)) {
    const {profile,active}=await request('load');
    if(iceMode(profile)) {
      if(api?.runtime?.id) {
        const result=await api.runtime.sendMessage({action:'send-ice',operation:action,code:fields.code,key:active});
        if(!result?.ok)throw new Error(result?.error??'No response from the extension');
        return result;
      }
      const {performIce}=await import('./ice-operation.js');return performIce(action,fields.code,undefined,active);
    }
  }
  const message={action,...fields};
  const response=api?.runtime?.id?await api.runtime.sendMessage(message):await (await import('./browser-client.js')).queuedDispatch(message);
  if(!response?.ok)throw new Error(response?.error??'No response from the extension');return response;
}
export async function ensurePermission(profile,action='status') {
  if(['open','close'].includes(action)&&iceMode(profile))return;
  if(!api?.permissions||!profile)return;
  const origin=new URL(profile.server_url).origin;
  const allowed=await api.permissions.request({origins:['https://'+new URL(origin).hostname+'/*']});
  if(!allowed)throw new Error(t('Allow access to this server: {origin}',{origin}));
}
export function showError(error) {document.querySelector('#message').textContent=t(error.message);}
export async function busy(work) {
  const buttons=[...document.querySelectorAll('button')];buttons.forEach(button=>{button.disabled=true;});
  try {await work();}catch(error){showError(error);}finally{buttons.forEach(button=>{button.disabled=false;});}
}

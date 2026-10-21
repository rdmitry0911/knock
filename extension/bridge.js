import {t} from './i18n.js';
export const api=globalThis.browser??globalThis.chrome;
export async function request(action,fields={}) {
  if(['open','close'].includes(action)) {
    const {profile,active}=await request('load');
    if(!profile)throw new Error('Import a server-issued profile first');
    if(api?.runtime?.id) {
      const result=await api.runtime.sendMessage({action:'send-ice',operation:action,key:active});
      if(!result?.ok)throw new Error(result?.error??'No response from the extension');
      return result;
    }
    const {performIce}=await import('./ice-operation.js');return performIce(action,undefined,undefined,active);
  }
  const response=api?.runtime?.id?await api.runtime.sendMessage({action,...fields}):await (await import('./browser-client.js')).queuedDispatch({action,...fields});
  if(!response?.ok)throw new Error(response?.error??'No response from the extension');return response;
}
export function showError(error) {document.querySelector('#message').textContent=t(error.message);}
export async function busy(work) {
  const buttons=[...document.querySelectorAll('button')];buttons.forEach(button=>{button.disabled=true;});
  try {await work();}catch(error){showError(error);}finally{buttons.forEach(button=>{button.disabled=false;});}
}

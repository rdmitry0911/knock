import {queuedDispatch} from './browser-client.js';
export function registerBackground(sendIce) {
  const api=globalThis.browser??globalThis.chrome;
  let iceQueue=Promise.resolve();
  api.runtime.onMessage.addListener((message,sender,reply)=>{
    if(message.target==='knock-offscreen')return false;
    if(sender.id!==api.runtime.id||!sender.url?.startsWith(api.runtime.getURL('')))return false;
    let result;
    if(message.action==='send-ice') {
      if(!['open','close'].includes(message.operation))return false;
      result=iceQueue.then(()=>sendIce(message));iceQueue=result.catch(()=>{});
    }else result=queuedDispatch(message);
    result.then(reply,error=>reply({ok:false,error:error.message}));return true;
  });
}

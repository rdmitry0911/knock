import { queuedDispatch } from './browser-client.js';
const api=globalThis.browser??globalThis.chrome;
api.runtime.onMessage.addListener((message,sender,reply)=>{
  if(sender.id!==api.runtime.id||!sender.url?.startsWith(api.runtime.getURL('')))return false;
  queuedDispatch(message).then(reply,error=>reply({ok:false,error:error.message}));
  return true;
});
const action=api.action??api.browserAction;
action?.onClicked.addListener(()=>api.tabs.create({url:api.runtime.getURL('app.html')}));

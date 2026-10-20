// Chromium's WebRTC document stays alive when the toolbar popup closes.
chrome.runtime.onMessage.addListener((message,sender,reply)=>{
  if(message.target!=='knock-offscreen'||sender.id!==chrome.runtime.id)return false;
  if(!['open','close'].includes(message.operation))return false;
  import('./ice-operation.js').then(({performIce})=>performIce(message.operation,message.code,request=>chrome.runtime.sendMessage(request),message.key)).then(reply,error=>reply({ok:false,error:error.message}));return true;
});

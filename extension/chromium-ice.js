let creating;
export async function sendIce(message) {
  if(!await chrome.offscreen.hasDocument()) {
    creating??=chrome.offscreen.createDocument({url:'offscreen.html',reasons:['WEB_RTC'],justification:'Complete an authenticated ICE knock when the toolbar popup closes.'}).finally(()=>{creating=null;});
    await creating;
  }
  try {return await chrome.runtime.sendMessage({target:'knock-offscreen',operation:message.operation,code:message.code,key:message.key});}
  finally {if(await chrome.offscreen.hasDocument())await chrome.offscreen.closeDocument();}
}

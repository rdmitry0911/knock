// Actual Chrome APK on an Android AVD, using Playwright's Android/CDP bridge.
import {readFile,writeFile} from 'node:fs/promises';
import net from 'node:net';
import {messageKey} from '../extension/i18n.js';
const {_android}=await import(process.env.PLAYWRIGHT_MODULE||'playwright');
const work=process.argv[2];
const rpc=op=>new Promise((resolve,reject)=>{const socket=net.createConnection(work+'/control.sock');let data='';socket.on('connect',()=>socket.write(JSON.stringify({op})));socket.on('data',b=>data+=b);socket.on('end',()=>resolve(JSON.parse(data)));socket.on('error',reject);});
const expectedCache=(await readFile(new URL('../extension/sw.js',import.meta.url),'utf8')).match(/const CACHE='([^']+)'/)[1];
const bundle=JSON.parse(await readFile(work+'/bundle.json','utf8')),enrollment=await readFile(work+'/enrollment.txt','utf8');
const {web_url}=JSON.parse(await readFile(work+'/ready.json','utf8'));
const [device]=await _android.devices();if(!device)throw new Error('Android AVD not found');
const context=await device.launchBrowser({ignoreHTTPSErrors:true,args:['--no-first-run','--disable-fre','--no-default-browser-check','--ignore-certificate-errors']});
const checks=[],errors=[];
async function localized(page,source,values={}) {const lang=await page.locator('html').getAttribute('lang');const catalog=JSON.parse(await readFile(new URL('../extension/_locales/'+lang.replace('-','_')+'/messages.json',import.meta.url),'utf8'));return (catalog[messageKey(source)]?.message??source).replace(/\{(\w+)\}/g,(all,key)=>values[key]??all);}
async function expectMessage(page,source,values={}) {await page.locator('#message').filter({hasText:await localized(page,source,values)}).waitFor({timeout:15000});}
try {
  const page=await context.newPage();page.on('pageerror',e=>errors.push(e.message));
  await page.goto(web_url);await page.locator('#message').filter({hasText:/\S/}).waitFor();
  await page.evaluate(async()=>{await navigator.serviceWorker.ready;});
  await page.waitForFunction(async expected=>{const keys=await caches.keys();return keys.includes(expected)&&!keys.some(k=>k.startsWith('knock-control-shell-')&&k!==expected);},expectedCache,{timeout:30000});
  await page.reload();await page.locator('#message').filter({hasText:/\S/}).waitFor();
  if(await page.locator('#control-panel').isVisible())await page.locator('#add-profile').click();
  await page.locator('#import-details').evaluate(node=>{node.open=true;});
  await page.locator('#import-text').fill(enrollment);await page.locator('#import-button').click();await expectMessage(page,'Profile imported. Press ON.');
  await device.shell('uiautomator dump /sdcard/knock-ui.xml');
  const native=(await device.shell('cat /sdcard/knock-ui.xml')).toString();
  if(native.includes('Chrome notifications')) {
    const node=native.match(/<node[^>]*text="No thanks"[^>]*>/)?.[0],bounds=node?.match(/bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"/);
    if(bounds){const [,x1,y1,x2,y2]=bounds.map(Number);await device.shell(`input tap ${Math.floor((x1+x2)/2)} ${Math.floor((y1+y2)/2)}`);}
  }
  if(await page.evaluate(()=>location.hash))throw new Error('Enrollment secret left in URL');
  await page.reload();await expectMessage(page,'Press ON.');
  checks.push('Offline QR text imported without visiting the knock server; profile survives reload');
  const ua=await page.evaluate(()=>navigator.userAgent);console.log(JSON.stringify({phase:'import',ua}));
  const service=await context.newPage();
  async function reachable() {
    await service.bringToFront();
    try {await service.goto('http://203.0.113.1:23456/?t='+Date.now(),{timeout:2500,waitUntil:'domcontentloaded'});return (await service.title())==='Protected service OK';}catch{return false;}finally{await service.goto('about:blank');}
  }
  async function action(which) {
    await page.bringToFront();await page.locator('#'+which).click();
    await expectMessage(page,'Signed UDP knock {operation} sent. No server response was requested.',{operation:which==='open'?'ON':'OFF'});
    return await rpc('status');
  }
  if(await reachable())throw new Error('Service reachable before ON');
  await page.evaluate(async()=>{await navigator.serviceWorker.ready;});
  await page.waitForFunction(async expected=>{const keys=await caches.keys();return keys.includes(expected)&&!keys.some(key=>key.startsWith('knock-control-shell-')&&key!==expected);},expectedCache,{timeout:30000});
  const before=await rpc('close-web');
  await page.reload();await expectMessage(page,'Press ON.');checks.push('Cached web app shell and stored profile reload with the HTTPS server stopped');
  const on=await action('open');console.log(JSON.stringify({phase:'on',grants:on.grants,captured_packets:on.captures.length}));
  if(!Object.values(on.grants).includes(true)||!await reachable())throw new Error('ICE ON did not open protected service');
  const off=await action('close');if(Object.values(off.grants).includes(true)||await reachable())throw new Error('ICE OFF did not close protected service');
  checks.push('ICE ON/OFF opens/closes a real protected HTTP service with static bootstrap host stopped; no control API installed');
  await rpc('restart-daemon');const replay=await rpc('replay');if(Object.values(replay.grants).includes(true))throw new Error('Replay reopened service');checks.push('Captured ON rejected after daemon restart');
  await action('open');await new Promise(r=>setTimeout(r,17000));if(await reachable())throw new Error('Idle timeout failed');checks.push('Idle access expires without protected service traffic');
  const after=await rpc('status');if(after.api_requests!==before.api_requests||after.knock_udp_listener||after.stun_secret_leaks||!after.daemon_alive)throw new Error('Transport invariants failed');
  await page.bringToFront();await page.screenshot({path:work+'/chrome-android.png'});await device.screenshot({path:work+'/chrome-android-device.png'});
  const removedKey=await page.locator('#profiles').inputValue();
  page.once('dialog',dialog=>dialog.accept());await page.locator('#delete-profile').click();await expectMessage(page,'Profile removed from this browser.');
  await page.reload();await page.locator('#message').filter({hasText:/\S/}).waitFor();if(await page.locator('#profiles option').evaluateAll((nodes,key)=>nodes.some(n=>n.value===key),removedKey))throw new Error('Deleted profile returned');checks.push('Local profile deletion persists after reload with static host stopped');
  if(errors.length)throw new Error(errors.join('; '));
  const result={result:'PASS',browser:'Chrome Android',client_cache:expectedCache,interface_language:await page.locator('html').getAttribute('lang'),user_agent:ua,checks,api_requests_during_ice:after.api_requests-before.api_requests,knock_udp_listener:after.knock_udp_listener,certificate_exception:'Self-signed certificate accepted only in this disposable test browser'};
  await writeFile(work+'/chrome-report.json',JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result));
} catch(error) {for(const page of context.pages()) {try {console.error(JSON.stringify({diagnostic:true,message:await page.locator('#message').textContent({timeout:1000}),page_errors:errors,cache_names:await page.evaluate(()=>caches.keys())}));}catch{}}throw error;} finally {await context.close();await device.close();}

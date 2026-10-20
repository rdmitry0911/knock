// Actual Chrome APK on an Android AVD, using Playwright's Android/CDP bridge.
import {readFile,writeFile} from 'node:fs/promises';
import net from 'node:net';
const {_android}=await import(process.env.PLAYWRIGHT_MODULE||'playwright');
const work=process.argv[2];
const rpc=op=>new Promise((resolve,reject)=>{const socket=net.createConnection(work+'/control.sock');let data='';socket.on('connect',()=>socket.write(JSON.stringify({op})));socket.on('data',b=>data+=b);socket.on('end',()=>resolve(JSON.parse(data)));socket.on('error',reject);});
const bundle=JSON.parse(await readFile(work+'/bundle.json','utf8')),enrollment=await readFile(work+'/enrollment.txt','utf8');
const [device]=await _android.devices();if(!device)throw new Error('Android AVD not found');
const context=await device.launchBrowser({ignoreHTTPSErrors:true,args:['--no-first-run','--disable-fre','--no-default-browser-check','--ignore-certificate-errors']});
const checks=[],errors=[];
try {
  const page=await context.newPage();page.on('pageerror',e=>errors.push(e.message));
  await page.goto(enrollment);await page.locator('#message').filter({hasText:'Профиль импортирован'}).waitFor();
  await device.shell('uiautomator dump /sdcard/knock-ui.xml');
  const native=(await device.shell('cat /sdcard/knock-ui.xml')).toString();
  if(native.includes('Chrome notifications')) {
    const node=native.match(/<node[^>]*text="No thanks"[^>]*>/)?.[0],bounds=node?.match(/bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"/);
    if(bounds){const [,x1,y1,x2,y2]=bounds.map(Number);await device.shell(`input tap ${Math.floor((x1+x2)/2)} ${Math.floor((y1+y2)/2)}`);}
  }
  if(await page.evaluate(()=>location.hash))throw new Error('Enrollment secret left in URL');
  await page.locator('#connection-panel summary').click();await page.locator('[name=stun_server]').fill(bundle.stun_server);await page.locator('#connection-form button').click();await page.locator('#message').filter({hasText:'Подключение сохранено'}).waitFor();
  await page.reload();await page.locator('#message').filter({hasText:'Нажмите ON'}).waitFor();
  checks.push('QR enrollment URL imported and removed from URL; profile survives reload');
  const ua=await page.evaluate(()=>navigator.userAgent);console.log(JSON.stringify({phase:'import',ua}));
  const service=await context.newPage();
  async function reachable() {
    await service.bringToFront();
    try {await service.goto('http://203.0.113.1:23456/?t='+Date.now(),{timeout:2500,waitUntil:'domcontentloaded'});return (await service.title())==='Protected service OK';}catch{return false;}
  }
  async function action(which) {
    await page.bringToFront();await page.locator('#'+which).click();
    await page.locator('#message').filter({hasText:'UDP-knock '+(which==='open'?'ON':'OFF')+' отправлен'}).waitFor({timeout:15000});
    return await rpc('status');
  }
  if(await reachable())throw new Error('Service reachable before ON');
  await page.evaluate(async()=>{await navigator.serviceWorker.ready;});
  const before=await rpc('close-api');
  await page.reload();await page.locator('#message').filter({hasText:'Нажмите ON'}).waitFor();checks.push('Cached web app shell and stored profile reload with the HTTPS server stopped');
  const on=await action('open');console.log(JSON.stringify({phase:'on',grants:on.grants,captured_packets:on.captures.length}));
  if(!Object.values(on.grants).includes(true)||!await reachable())throw new Error('ICE ON did not open protected service');
  const off=await action('close');if(Object.values(off.grants).includes(true)||await reachable())throw new Error('ICE OFF did not close protected service');
  checks.push('ICE ON/OFF opens/closes a real protected HTTP service with management HTTPS listener closed');
  await rpc('restart-daemon');const replay=await rpc('replay');if(Object.values(replay.grants).includes(true))throw new Error('Replay reopened service');checks.push('Captured ON rejected after daemon restart');
  await action('open');await new Promise(r=>setTimeout(r,17000));if(await reachable())throw new Error('Idle timeout failed');checks.push('Idle access expires without protected service traffic');
  const after=await rpc('status');if(after.api_requests!==before.api_requests||after.knock_udp_listener||after.stun_secret_leaks||!after.daemon_alive)throw new Error('Transport invariants failed');
  await rpc('open-api');await page.bringToFront();await page.locator('#status').click();await page.locator('#state').filter({hasText:'Доступ выключен'}).waitFor();
  await page.locator('#settings-panel summary').click();await page.locator('[name=idle_timeout]').fill('12');await page.locator('#settings-form button').click();await page.locator('#message').filter({hasText:'Настройки сохранены'}).waitFor();checks.push('Signed HTTPS status and profile configuration work on Android');
  await rpc('close-api');await action('open');if(!await reachable())throw new Error('Updated revision failed');await action('close');
  await page.bringToFront();await page.screenshot({path:work+'/chrome-android.png'});await device.screenshot({path:work+'/chrome-android-device.png'});
  if(errors.length)throw new Error(errors.join('; '));
  const result={result:'PASS',browser:'Chrome Android',user_agent:ua,checks,api_requests_during_ice:after.api_requests-before.api_requests,knock_udp_listener:after.knock_udp_listener,certificate_exception:'Self-signed certificate accepted only in this disposable test browser'};
  await writeFile(work+'/chrome-report.json',JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result));
} finally {await context.close();await device.close();}

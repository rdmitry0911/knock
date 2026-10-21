// JSON RPC test client; actual ICE ON/OFF always comes from the browser UI.
import {readFile,mkdtemp,rm} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {tmpdir} from 'node:os';
import {resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import readline from 'node:readline';
import net from 'node:net';
import dgram from 'node:dgram';
const pw=await import(process.env.PLAYWRIGHT_MODULE||'playwright');
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const config=JSON.parse(await readFile(process.argv[3],'utf8')),engine=process.argv[2],home=await mkdtemp(resolve(tmpdir(),'ice-browser-'));
let context,browser,held,noise,noiseTimer,noiseCount=0;
const apiRequests=[];
try {
  if(engine==='chromium') {
    const extension=resolve(root,'dist/chromium-browser');
    const id=createHash('sha256').update(extension).digest('hex').slice(0,32).replace(/[0-9a-f]/g,c=>String.fromCharCode(97+parseInt(c,16)));
    context=await pw.chromium.launchPersistentContext(home,{channel:'chromium',headless:true,args:['--no-sandbox',`--disable-extensions-except=${extension}`,`--load-extension=${extension}`]});
    const page=await context.newPage();await page.goto(`chrome-extension://${id}/app.html`);
  } else {
    browser=await pw[engine].launch({headless:true});context=await browser.newContext({ignoreHTTPSErrors:true,viewport:{width:390,height:844}});
    const page=await context.newPage();await page.goto('https://203.0.113.1:18443/app/');
  }
  const page=context.pages().at(-1),errors=[];
  page.on('pageerror',e=>errors.push(e.message));page.on('request',q=>{if(q.url().includes('/v1/control'))apiRequests.push(q.url());});
  await page.locator('#message').filter({hasText:engine==='chromium'?'Import a server-issued JSON profile':'Import your server-issued QR'}).waitFor();
  await page.locator('#import-file').setInputFiles(config.bundle_file);
  await page.locator('#message').filter({hasText:'Profile imported'}).waitFor();
  await page.evaluate(async()=>{await import('./ice-client.js');});
  console.log(JSON.stringify({ready:true}));
  async function tcp(keep=false) {
    const socket=net.createConnection({host:config.bundle.knock_host,port:config.service});socket.setTimeout(500);
    const ok=await new Promise(resolve=>{socket.once('connect',()=>socket.write('ping'));socket.once('data',b=>resolve(b.toString()==='ping'));socket.once('error',()=>resolve(false));socket.once('timeout',()=>resolve(false));});
    if(keep&&ok)held=socket;else socket.destroy();return ok;
  }
  for await(const line of readline.createInterface({input:process.stdin})) {
    const q=JSON.parse(line);let result;
    try {
      if(['on','off','on-detached','off-detached'].includes(q.op)) {
        const action=q.op.startsWith('on')?'on':'off';
        await page.locator(action==='on'?'#open':'#close').click();
        if(q.op.endsWith('-detached')){const url=page.url().replace('/app.html','/popup.html');await page.waitForTimeout(100);await page.goto('about:blank');await page.waitForTimeout(5500);await page.goto(url);await page.locator('#message').filter({hasText:'Press ON'}).waitFor();}
        else await page.locator('#message').filter({hasText:'UDP knock '+(action==='on'?'ON':'OFF')+' sent'}).waitFor({timeout:12000});
        result={sent:true,apiRequests:apiRequests.length,errors,debug:await page.evaluate(()=>window.iceDebug??[])};
      } else if(q.op==='tcp')result={reachable:await tcp()};
      else if(q.op==='hold')result={reachable:await tcp(true)};
      else if(q.op==='held')result={reachable:await new Promise(r=>{held.once('data',()=>r(true));held.once('timeout',()=>r(false));held.once('error',()=>r(false));held.write('ping');})};
      else if(q.op==='close-stream'){held?.destroy();held=null;result={ok:true};}
      else if(q.op==='noise-start') {
        noise=dgram.createSocket('udp4');const data=Buffer.alloc(212,0x71);data.set([0,1,0,192,0x21,0x12,0xa4,0x42]);
        noiseTimer=setInterval(()=>{for(let i=0;i<100;i++){noise.send(data,config.bundle.settings.base,config.bundle.knock_host);noiseCount++;}},5);result={ok:true};
      }
      else if(q.op==='raw') {
        const udp=dgram.createSocket('udp4');await new Promise((r,j)=>udp.send(Buffer.from(q.packet,'base64'),config.bundle.settings.base,config.bundle.knock_host,e=>e?j(e):r()));udp.close();result={ok:true};
      } else if(q.op==='token') {
        result=await page.evaluate(async({bundle,source,delta,revision})=>{const m=await import('./browser-client.js');return {token:await m.makeIceToken({...bundle,revision:revision??bundle.revision},'open',source,Date.now(),crypto.getRandomValues(new Uint8Array(16)),Date.now()+delta)};},{bundle:config.bundle,source:q.source,delta:q.delta??0,revision:q.revision});
      } else if(q.op==='send-token') {
        await page.evaluate(async({bundle,token})=>{const m=await import('./ice-client.js');await m.sendIce(bundle.knock_host,bundle.settings.base,token,800);},{bundle:config.bundle,token:q.token});result={ok:true};
      } else if(q.op==='stop') {clearInterval(noiseTimer);noise?.close();noise=null;console.log(JSON.stringify({ok:true,apiRequests:apiRequests.length,errors,noise_packets:noiseCount}));break;}
      else throw new Error('Unknown operation');
      console.log(JSON.stringify(result));
    } catch(e){console.log(JSON.stringify({error:e.message,ui:await page.locator('#message').textContent()}));}
  }
} finally {clearInterval(noiseTimer);noise?.close();held?.destroy();await context?.close();await browser?.close();await rm(home,{recursive:true,force:true});}

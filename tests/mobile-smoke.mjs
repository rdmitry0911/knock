// Standalone mobile profile UI and real QR/camera pipeline; no control API.
import {mkdtemp,readFile,rm,access} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawn,execFileSync} from 'node:child_process';
import assert from 'node:assert/strict';
const playwright=await import(process.env.PLAYWRIGHT_MODULE||'playwright');
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..'),home=await mkdtemp(resolve(tmpdir(),'knock-mobile-'));
let fixture;
try {
 fixture=spawn('python3',[resolve(root,'tests/client_fixture.py'),resolve(home,'server')],{stdio:['ignore','ignore','inherit']});
 for(let i=0;i<200;i++){try{await access(resolve(home,'server/ready.json'));break;}catch{assert.equal(fixture.exitCode,null);await new Promise(r=>setTimeout(r,50));}}
 const {origin}=JSON.parse(await readFile(resolve(home,'server/ready.json'),'utf8'));
 const alice=JSON.parse(await readFile(resolve(home,'server/alice.json'),'utf8'));
  const camera=resolve(home,'camera.y4m');
  execFileSync('/usr/bin/python3',['-c',
    "import sys,json;sys.path.insert(0,'controller');import qr_codec;from vendor.qrcodegen import QrCode;from pathlib import Path;b=json.loads(Path(sys.argv[1]).read_text());q=QrCode.encode_text(qr_codec.enrollment_url(b),QrCode.Ecc.MEDIUM);size=960;scale=min(6,size//(q.get_size()+8));off=(size-q.get_size()*scale)//2;y=bytearray([235])*(size*size)\nfor row in range(size):\n for col in range(size):\n  if q.get_module((col-off)//scale,(row-off)//scale):y[row*size+col]=16\nPath(sys.argv[2]).write_bytes(b'YUV4MPEG2 W960 H960 F4:1 Ip A1:1 C420jpeg\\nFRAME\\n'+y+bytes([128])*(size*size//2))",
    resolve(home,'server/alice.json'),camera],{cwd:root});
 for(const engine of (process.env.BROWSER_ENGINES||'chromium,firefox').split(',')) {
  const browser=await playwright[engine].launch({headless:true,...(engine==='chromium'?{args:['--use-fake-ui-for-media-stream','--use-fake-device-for-media-stream',`--use-file-for-fake-video-capture=${camera}`]}:{})});
  try {
   const context=await browser.newContext({userAgent:'Mozilla/5.0 (Linux; Android 15) Mobile',viewport:{width:390,height:844},hasTouch:true});
   const page=await context.newPage(),errors=[],requests=[];page.on('pageerror',e=>errors.push(e.message));page.on('request',r=>requests.push({url:r.url(),method:r.method()}));
   await page.goto(origin+'/');await page.locator('#message').filter({hasText:'Import your server-issued QR'}).waitFor();
   assert.equal(await page.locator('#status,#settings-panel,#connection-panel').count(),0);
   await page.locator('#qr-image').setInputFiles(resolve(home,'server/alice.png'));await page.locator('#message').filter({hasText:'Profile imported'}).waitFor();
   await page.reload();await page.locator('#message').filter({hasText:'Press ON'}).waitFor();
   if(engine==='chromium') {
    await context.grantPermissions(['camera'],{origin});await page.locator('#add-profile').click();await page.locator('#qr-start').click();
    await page.locator('#message').filter({hasText:'Profile imported'}).waitFor();assert.equal(await page.locator('#qr-camera').isVisible(),false);
   }
   await page.locator('#add-profile').click();await page.locator('#qr-image').setInputFiles(resolve(home,'server/bob.png'));await page.locator('#profiles option:checked').filter({hasText:'Bob'}).waitFor({state:'attached'});
   await page.locator('#profiles').selectOption({label:'Alice'});await page.locator('#message').filter({hasText:'Press ON'}).waitFor();
   page.once('dialog',d=>d.accept());await page.locator('#delete-profile').click();await page.locator('#message').filter({hasText:'Profile removed'}).waitFor();
   assert.equal(await page.locator('#profiles option:checked').textContent(),'Bob');await page.reload();await page.locator('#message').filter({hasText:'Press ON'}).waitFor();
   assert.equal(await page.locator('#profiles option').count(),1);assert.ok(!requests.some(r=>r.method==='POST'||r.url.includes(alice.secret)||r.url.includes('kc3_')));
   assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);assert.deepEqual(errors,[]);
   console.log(`PASS: ${engine} mobile viewport: v3 QR image, stored profiles, selection/deletion, no API traffic; camera pipeline ${engine==='chromium'?'passed with simulated frames':'not simulated'}`);
   await context.close();
  }finally{await browser.close();}
 }
}finally{if(fixture){fixture.kill();await new Promise(r=>fixture.once('exit',r));}await rm(home,{recursive:true,force:true});}

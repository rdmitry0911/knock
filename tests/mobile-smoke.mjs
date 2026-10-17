/* Node >=20 + Playwright. Real HTTPS/API and real QR decoding; fixture firewall
 * is a stub. Test certificates are accepted only by the test browser context. */
import {mkdtemp,readFile,writeFile,rm,access,cp} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {resolve,dirname} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {spawn,execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import assert from 'node:assert/strict';
const playwright=await import(process.env.PLAYWRIGHT_MODULE||'playwright');
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const home=await mkdtemp(resolve(tmpdir(),'knock-mobile-'));
let fixture;
try {
  fixture=spawn('/usr/bin/python3',[resolve(root,'tests/api_fixture.py'),resolve(home,'server')],{stdio:['ignore','ignore','inherit']});
  for(let i=0;i<200;i++){try{await access(resolve(home,'server/ready.json'));break;}catch{if(fixture.exitCode!==null)throw new Error('Fixture exited');await new Promise(r=>setTimeout(r,50));}}
  const alice=JSON.parse(await readFile(resolve(home,'server/alice.json'),'utf8'));
  const url=(await readFile(resolve(home,'server/alice-url.txt'),'utf8')).trim();
  const module=await import(pathToFileURL(resolve(root,'extension/browser-client.js')));
  const fixed=JSON.parse(execFileSync('/usr/bin/python3',['-c',
    "import sys,json,base64;sys.path.insert(0,'controller');import common;from pathlib import Path;b=common.client_bundle(json.loads(Path(sys.argv[1]).read_text()));c={**b['settings'],'secret':b['secret'],'profile_id':b['profile_id']};n=1700000000;print(json.dumps({'sequence':common.sequence(c,'open','192.0.2.7',now=n),'confirmation':base64.b64encode(common.confirmation(c,'open','192.0.2.7',now=n,nonce=bytes(16))).decode(),'signature':common.api_signature(b['secret'],'1700000000','0'*32,b'{\"action\":\"status\"}')}))",
    resolve(home,'server/alice.json')],{cwd:root,encoding:'utf8'}));
  assert.equal(await module.totp('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',59),'287082');
  const computed=await module.makeProof(alice,'open','192.0.2.7','',1700000000,new Uint8Array(16));
  assert.deepEqual(computed.sequence,fixed.sequence);assert.equal(computed.confirmation,fixed.confirmation);
  assert.equal(await module.apiSignature(alice.secret,'1700000000','0'.repeat(32),'{"action":"status"}'),fixed.signature);
  console.log('PASS: JavaScript/Python TOTP, sequences, confirmation and API HMAC compatibility');
  const camera=resolve(home,'camera.y4m');
  execFileSync('/usr/bin/python3',['-c',
    "import sys,json;sys.path.insert(0,'controller');import qr_codec;from vendor.qrcodegen import QrCode;from pathlib import Path;b=json.loads(Path(sys.argv[1]).read_text());q=QrCode.encode_text(qr_codec.enrollment_url(b),QrCode.Ecc.MEDIUM);size=960;scale=min(6,size//(q.get_size()+8));off=(size-q.get_size()*scale)//2;y=bytearray([235])*(size*size)\nfor row in range(size):\n for col in range(size):\n  if q.get_module((col-off)//scale,(row-off)//scale):y[row*size+col]=16\nPath(sys.argv[2]).write_bytes(b'YUV4MPEG2 W960 H960 F4:1 Ip A1:1 C420jpeg\\nFRAME\\n'+y+bytes([128])*(size*size//2))",
    resolve(home,'server/alice.json'),camera],{cwd:root});
  for(const engine of (process.env.BROWSER_ENGINES||'chromium,firefox').split(',')) {
    const browser=await playwright[engine].launch({headless:true,...(engine==='chromium'?{args:['--ignore-certificate-errors','--use-fake-ui-for-media-stream','--use-fake-device-for-media-stream',`--use-file-for-fake-video-capture=${camera}`]}: {})});
    try {
      const context=await browser.newContext({ignoreHTTPSErrors:true,viewport:{width:390,height:844},hasTouch:true});
      const page=await context.newPage(),errors=[],requests=[];
      page.on('pageerror',e=>errors.push(e.message));page.on('request',r=>requests.push(r.url()));
      await page.goto(url);await page.locator('#message').filter({hasText:'Профиль импортирован'}).waitFor();
      assert.equal(new URL(page.url()).hash,'');assert.ok(!requests.some(u=>u.includes(alice.secret)||u.includes('kc2_')));
      await page.locator('#open').click();await page.locator('#state').filter({hasText:'Доступ включён'}).waitFor();
      assert.ok(await page.locator('#import-panel').isHidden());
      await page.reload();await page.locator('#message').filter({hasText:'Нажмите ON'}).waitFor();
      assert.ok(await page.locator('#import-panel').isHidden());
      await page.locator('#close').click();await page.locator('#state').filter({hasText:'Доступ выключен'}).waitFor();
      await page.locator('#add-profile').click();
      await page.locator('#qr-image').setInputFiles(resolve(home,'server/bob.png'));
      await page.locator('#message').filter({hasText:'Профиль импортирован'}).waitFor();
      assert.equal(await page.locator('#profiles option:checked').textContent(),'Bob');
      await page.locator('#open').click();await page.locator('#state').filter({hasText:'Доступ включён'}).waitFor();
      await page.locator('#settings-panel summary').click();await page.locator('[name=idle_timeout]').fill('30');
      await page.locator('#settings-form button').click();await page.locator('#message').filter({hasText:'Настройки сохранены'}).waitFor();
      await page.locator('#profiles').selectOption({label:'Alice'});await page.locator('#message').filter({hasText:'Нажмите ON'}).waitFor();
      await page.locator('#status').click();await page.locator('#state').filter({hasText:'Доступ выключен'}).waitFor();
      assert.equal(await page.locator('[name=idle_timeout]').inputValue(),'10');
      // Camera import uses a deterministic QR frame on Chromium's real media API.
      if(engine==='chromium') {
        await context.grantPermissions(['camera'],{origin:alice.server_url});
        await page.locator('#add-profile').click();await page.locator('#qr-start').click();
        await page.locator('#message').filter({hasText:'Профиль импортирован'}).waitFor();
        assert.ok(await page.locator('#qr-camera').isHidden());
        const result=await page.evaluate(async origin=>{
          const response=await fetch(origin+'/app/app.webmanifest');const manifest=await response.json();
          await Promise.race([navigator.serviceWorker.ready,new Promise((_,reject)=>setTimeout(()=>reject(new Error('Service worker did not become ready')),8000))]);
          return {manifest:manifest.display,worker:!!navigator.serviceWorker.controller,overflow:document.documentElement.scrollWidth>innerWidth};
        },alice.server_url);
        assert.equal(result.manifest,'standalone');assert.equal(result.worker,true);assert.equal(result.overflow,false);
        console.log('PASS: camera video pipeline decodes QR and stops capture (simulated camera frames)');
      }
      assert.deepEqual(errors,[]);
      const response=await context.request.get(alice.server_url+'/app/../settings.json');assert.equal(response.status(),404);
      console.log(`PASS: ${engine} mobile viewport: QR link + PNG import, remembered profiles, automatic IP, ON/OFF, isolated settings, no secret in HTTP URLs`);
      await context.close();
    } finally {await browser.close();}
  }
  // A real MV3 background service worker fetches the API without Native Messaging.
  // Grant only this fixture's host at install time in the TEST COPY; production
  // requests its optional host permission from the first ON click.
  const extension=resolve(home,'extension');await cp(resolve(root,'dist/chromium-browser'),extension,{recursive:true});
  const manifest=JSON.parse(await readFile(resolve(extension,'manifest.json'),'utf8'));
  manifest.host_permissions=['https://127.0.0.1/*'];await writeFile(resolve(extension,'manifest.json'),JSON.stringify(manifest));
  const id=createHash('sha256').update(extension).digest('hex').slice(0,32).replace(/[0-9a-f]/g,ch=>String.fromCharCode(97+parseInt(ch,16)));
  const context=await playwright.chromium.launchPersistentContext(resolve(home,'chrome'),{channel:'chromium',headless:true,ignoreHTTPSErrors:true,
    args:[`--disable-extensions-except=${extension}`,`--load-extension=${extension}`,'--ignore-certificate-errors']});
  try {
    const page=await context.newPage(),errors=[];page.on('pageerror',e=>errors.push(e.message));
    await page.goto(`chrome-extension://${id}/app.html`);await page.locator('#message').filter({hasText:'Импортируйте QR'}).waitFor();
    await page.locator('#qr-image').setInputFiles(resolve(home,'server/alice.png'));
    await page.locator('#message').filter({hasText:'Профиль импортирован'}).waitFor();
    await page.locator('#open').click();await page.locator('#state').filter({hasText:'Доступ включён'}).waitFor();
    await page.locator('#close').click();await page.locator('#state').filter({hasText:'Доступ выключен'}).waitFor();
    assert.deepEqual(errors,[]);console.log('PASS: Chromium HTTPS extension with service-worker storage and QR import, no native helper');
  } finally {await context.close();}
} finally {
  if(fixture){fixture.kill();await new Promise(resolve=>fixture.once('exit',resolve));}
  await rm(home,{recursive:true,force:true});
}

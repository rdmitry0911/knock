// Real browser rendering of all shipped locales, desktop JSON UI and toolbar popup.
import {readFile,writeFile,mkdtemp,rm,access} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {tmpdir} from 'node:os';
import {resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import assert from 'node:assert/strict';
import {messageKey,languages} from '../extension/i18n.js';
const pw=await import(process.env.PLAYWRIGHT_MODULE||'playwright');
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..'),home=await mkdtemp(resolve(tmpdir(),'knock-locales-'));
let fixture,browser,extensionContext;
const checks=[];
try {
  fixture=spawn('python3',[resolve(root,'tests/client_fixture.py'),resolve(home,'server')],{stdio:['ignore','ignore','inherit']});
  for(let n=0;n<200;n++){try{await access(resolve(home,'server/ready.json'));break;}catch{assert.equal(fixture.exitCode,null);await new Promise(r=>setTimeout(r,50));}}
  const {origin}=JSON.parse(await readFile(resolve(home,'server/ready.json'),'utf8'));
  const bundle=JSON.parse(await readFile(resolve(home,'server/alice.json'),'utf8'));
  const en=JSON.parse(await readFile(resolve(root,'extension/_locales/en/messages.json'),'utf8'));
  browser=await pw.chromium.launch();
  for(const locale of [...languages,'tr']) {
    const context=await browser.newContext({locale:locale.replace('_','-'),ignoreHTTPSErrors:true,viewport:{width:380,height:650}});
    try {
      const page=await context.newPage(),errors=[];page.on('pageerror',e=>errors.push(e.message));
      await page.goto(origin+'/');await page.locator('#message').filter({hasText:locale==='tr'?en[messageKey('Import a server-issued JSON profile.')].message:JSON.parse(await readFile(resolve(root,`extension/_locales/${locale}/messages.json`),'utf8'))[messageKey('Import a server-issued JSON profile.')].message}).waitFor();
      const dictionary=locale==='tr'?en:JSON.parse(await readFile(resolve(root,`extension/_locales/${locale}/messages.json`),'utf8'));
      assert.equal(await page.locator('h1').textContent(),dictionary[messageKey('Server access')].message);
      assert.equal(await page.locator('html').getAttribute('dir'),locale==='ar'?'rtl':'ltr');
      assert.equal(await page.locator('#qr-start').isVisible(),false);
      assert.equal(await page.locator('#qr-image').isVisible(),false);
      await page.locator('#import-file').setInputFiles(resolve(home,'server/alice.json'));
      await page.locator('#control-panel').waitFor();
      assert.equal(await page.locator('#status,#settings-panel,#connection-panel').count(),0);
      page.once('dialog',dialog=>dialog.accept());await page.locator('#delete-profile').click();
      await page.locator('#import-panel').waitFor();
      assert.equal(await page.locator('#message').textContent(),dictionary[messageKey('Profile removed from this browser.')].message);
      assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
      assert.deepEqual(errors,[]);checks.push({locale,translated:true,desktop_json:true,qr_hidden:true});
    }finally{await context.close();}
  }
  const path=resolve(root,'dist/chromium-browser');
  const id=createHash('sha256').update(path).digest('hex').slice(0,32).replace(/[0-9a-f]/g,c=>String.fromCharCode(97+parseInt(c,16)));
  extensionContext=await pw.chromium.launchPersistentContext(resolve(home,'chromium'),{channel:'chromium',headless:true,ignoreHTTPSErrors:true,args:[`--disable-extensions-except=${path}`,`--load-extension=${path}`,'--ignore-certificate-errors']});
  const page=await extensionContext.newPage();await page.goto(`chrome-extension://${id}/popup.html`);
  await page.locator('#message').filter({hasText:'Import a server-issued JSON profile'}).waitFor();
  assert.equal(await page.evaluate(()=>chrome.runtime.getManifest().action.default_popup),'popup.html');
  assert.equal(await page.locator('#qr-start').isVisible(),false);
  const box=await page.locator('body').boundingBox();assert.ok(box.width>=340&&box.width<=420,JSON.stringify(box));
  await page.locator('#import-file').setInputFiles(resolve(home,'server/alice.json'));await page.locator('#control-panel').waitFor();
  await page.close();
  const reopened=await extensionContext.newPage();await reopened.goto(`chrome-extension://${id}/popup.html`);await reopened.locator('#control-panel').waitFor();
  assert.equal(await reopened.locator('#profiles option:checked').textContent(),'Alice');
  await reopened.screenshot({path:resolve(root,'dist/popup-desktop.png'),clip:{x:0,y:0,width:380,height:Math.min(590,await reopened.evaluate(()=>document.body.scrollHeight))}});
  assert.equal(await reopened.evaluate(()=>chrome.runtime.getManifest().optional_host_permissions),undefined);
  await reopened.locator('#add-profile').click();await reopened.locator('#import-file').setInputFiles(resolve(home,'server/bob.json'));
  await reopened.locator('#profiles option:checked').filter({hasText:'Bob'}).waitFor({state:'attached'});
  reopened.once('dialog',dialog=>dialog.dismiss());await reopened.locator('#delete-profile').click();
  assert.equal(await reopened.locator('#profiles option').count(),2);
  reopened.once('dialog',dialog=>dialog.accept());await reopened.locator('#delete-profile').click();
  await reopened.locator('#profiles option:checked').filter({hasText:'Alice'}).waitFor({state:'attached'});
  await reopened.reload();await reopened.locator('#profiles option:checked').filter({hasText:'Alice'}).waitFor({state:'attached'});
  assert.equal(await reopened.locator('#profiles option').count(),1);
  const worker=extensionContext.serviceWorkers()[0]??await extensionContext.waitForEvent('serviceworker');
  await worker.evaluate(async()=>{await chrome.action.openPopup();});
  const cdp=await extensionContext.browser().newBrowserCDPSession();const nativeTargets=(await cdp.send('Target.getTargets')).targetInfos.filter(target=>target.url.endsWith('/popup.html'));assert.ok(nativeTargets.length>=2,'Native toolbar popup did not open');
  const result={result:'PASS',locales:checks,popup:{manifest_default_popup:true,native_toolbar_popup_opened:true,width:box.width,profile_survives_reopen:true,desktop_qr_hidden:true,profile_delete_cancel_and_fallback:true,deleted_profile_stays_deleted:true,no_settings_or_status:true},notes:'Desktop Chromium engine; locale rendering and JSON import/deletion are actual browser checks. ICE lifecycle has a separate kernel firewall test.'};
  await writeFile(resolve(root,'dist/localization-popup-test-report.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result));
}finally{
  await extensionContext?.close();await browser?.close();if(fixture){fixture.kill();await new Promise(r=>fixture.once('exit',r));}await rm(home,{recursive:true,force:true});
}

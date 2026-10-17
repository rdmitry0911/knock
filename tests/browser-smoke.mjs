/* Node >=20 + Playwright Chromium. Temporary HOME and real TLS API fixture;
 * fixture firewall/systemd are stubs. Real firewall: integration_netns.py.
 */
import { mkdtemp, mkdir, readFile, writeFile, rm, access } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { execFileSync, spawn } from 'node:child_process';
import assert from 'node:assert/strict';
const { chromium } = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const home = await mkdtemp(resolve(tmpdir(), 'knock-browser-v2-'));
const extension = resolve(root, 'dist/chromium');
const id = createHash('sha256').update(extension).digest('hex').slice(0,32).replace(/[0-9a-f]/g, ch => String.fromCharCode(97 + parseInt(ch,16)));
const env = {...process.env, HOME:home, XDG_CONFIG_HOME:resolve(home,'.config')};
let context, fixture;
try {
  fixture=spawn('/usr/bin/python3',[resolve(root,'tests/api_fixture.py'),resolve(home,'server')],{env,stdio:'ignore'});
  for(let i=0;i<100;i++) {
    try { await access(resolve(home,'server/ready.json')); break; }
    catch { if(fixture.exitCode!==null) throw new Error('API fixture exited'); await new Promise(resolve=>setTimeout(resolve,50)); }
  }
  const alice=JSON.parse(await readFile(resolve(home,'server/alice.json'),'utf8'));
  execFileSync('/usr/bin/python3',[resolve(root,'scripts/install-native.py'),'--chrome-id',id],{env});
  await mkdir(resolve(home,'browser/NativeMessagingHosts'),{recursive:true});
  await writeFile(resolve(home,'browser/NativeMessagingHosts/org.knock.control.json'),await readFile(resolve(home,'.config/chromium/NativeMessagingHosts/org.knock.control.json')));
  context=await chromium.launchPersistentContext(resolve(home,'browser'),{channel:'chromium',headless:true,env,
    args:[`--disable-extensions-except=${extension}`,`--load-extension=${extension}`]});
  const page=await context.newPage();const errors=[];
  page.on('pageerror',error=>errors.push(error.message));
  const origin=`chrome-extension://${id}`;
  await page.goto(`${origin}/options.html`);
  await page.locator('#message').filter({hasText:'Импортируйте JSON-файл'}).waitFor();
  assert.equal(await page.locator('#generate').count(),0);
  await page.locator('#import-file').setInputFiles(resolve(home,'server/alice.json'));
  await page.locator('#message').filter({hasText:'профиль импортирован'}).waitFor();
  await page.locator('#refresh').click();
  await page.locator('#message').filter({hasText:'получены с сервера'}).waitFor();
  assert.equal(await page.locator('[name=public_ip]').inputValue(),'127.0.0.1');
  await page.locator('[name=idle_timeout]').fill('15');
  await page.locator('#apply').click();
  await page.locator('#message').filter({hasText:'Настройки этого секрета применены'}).waitFor();
  await page.locator('#pairing').click();
  await page.locator('#pairing-secret').filter({hasText:alice.secret}).waitFor();
  await page.locator('#hide-pairing').click();
  assert.equal(await page.locator('#pairing-secret').textContent(),'');
  await page.locator('#import-file').setInputFiles(resolve(home,'server/bob.json'));
  await page.locator('#message').filter({hasText:'профиль импортирован'}).waitFor();
  await page.locator('#refresh').click();
  await page.locator('#message').filter({hasText:'получены с сервера'}).waitFor();
  assert.equal(await page.locator('[name=idle_timeout]').inputValue(),'20');
  await page.locator('#profiles').selectOption({label:`Alice · ${alice.server_url}`});
  await page.locator('#message').filter({hasText:'Профиль выбран'}).waitFor();
  await page.locator('#refresh').click();
  await page.locator('#message').filter({hasText:'получены с сервера'}).waitFor();
  assert.equal(await page.locator('[name=idle_timeout]').inputValue(),'15');
  const store=JSON.parse(await readFile(resolve(home,'.config/knock-control/profiles.json'),'utf8'));
  assert.equal(Object.keys(store.profiles).length,2);
  await page.goto(`${origin}/popup.html`);
  await page.locator('#server').filter({hasText:'Alice'}).waitFor();
  await page.locator('#status').click();
  await page.locator('#state').filter({hasText:'Доступ выключен'}).waitFor();
  await page.locator('#code').fill('123');await page.locator('#open').click();
  await page.locator('#message').filter({hasText:'Введите 6 цифр'}).waitFor();
  await page.locator('#code').fill('');await page.locator('#open').click();
  await page.locator('#message').filter({hasText:'Последовательность отправлена'}).waitFor({timeout:15000});
  assert.deepEqual(errors,[]);
  console.log('PASS: Chromium import/select two server-issued secrets, scoped settings via real pinned HTTPS, Google Authenticator, Native Messaging and signed knocks');
} finally {
  if(context) await context.close();
  if(fixture) { fixture.kill(); await new Promise(resolve=>fixture.once('exit',resolve)); }
  await rm(home,{recursive:true,force:true});
}

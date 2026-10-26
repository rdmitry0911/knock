import {request,busy,showError,api} from './bridge.js';
import {decodeEnrollment} from './profile-codec.js';
import {bindQRImport} from './qr.js';
import {t,translatePage} from './i18n.js';
translatePage();
const platform=api?.runtime?.getPlatformInfo?await api.runtime.getPlatformInfo():null;
const mobile=platform?.os==='android'||/Android|iPhone|iPad|iPod/i.test(navigator.userAgent)||(navigator.platform==='MacIntel'&&navigator.maxTouchPoints>1);
for(const node of document.querySelectorAll('[data-mobile-only]'))node.hidden=!mobile;
for(const node of document.querySelectorAll('[data-desktop-only]'))node.hidden=mobile;
if(!mobile){document.querySelector('#import-text').placeholder=t('Paste a JSON profile');document.querySelector('#import-details').open=true;}

const message=document.querySelector('#message'),profiles=document.querySelector('#profiles');
let current=null;
async function load() {
  const value=await request('load');current=value.profile;profiles.replaceChildren();
  for(const profile of value.profiles){const option=new Option(profile.name,profile.key);option.selected=profile.key===value.active;profiles.add(option);}
  document.querySelector('#import-panel').hidden=!!current;document.querySelector('#control-panel').hidden=!current;
  if(!current)return;
  document.querySelector('#server').textContent=current.knock_host;
}
async function importProfile(text) {
  if(!mobile&&typeof text==='string'&&!text.trim().startsWith('{'))throw new Error('Import a JSON profile on desktop.');
  await request('import',{bundle:typeof text==='string'?decodeEnrollment(text):text});await load();
  document.querySelector('#import-text').value='';message.textContent=t('Profile imported. Press ON.');
}
bindQRImport(text=>busy(()=>importProfile(text)),showError);
document.querySelector('#import-file').addEventListener('change',event=>busy(async()=>{const file=event.target.files[0];if(!file||file.size>32768)throw new Error('Choose a profile file up to 32 KiB');await importProfile(await file.text());event.target.value='';}));
document.querySelector('#import-button').addEventListener('click',()=>busy(()=>importProfile(document.querySelector('#import-text').value)));
document.querySelector('#add-profile').addEventListener('click',()=>{document.querySelector('#import-panel').hidden=false;document.querySelector('#import-panel').scrollIntoView({behavior:'smooth'});});
profiles.addEventListener('change',()=>busy(async()=>{await request('select',{key:profiles.value});await load();message.textContent=t('Press ON.');}));
document.querySelector('#delete-profile').addEventListener('click',()=>busy(async()=>{
  const key=profiles.value;
  if(!confirm(t('Remove profile {name} from this browser?',{name:current.name})))return;
  await request('remove',{key});await load();message.textContent=t('Profile removed from this browser.');
}));
for(const action of ['open','close'])document.querySelector('#'+action).addEventListener('click',()=>busy(async()=>{
  message.textContent=action==='open'?t('Enabling access…'):t('Disabling access…');
  const result=await request(action);await load();
  message.textContent=t('Signed knock {operation} sent for {ip}. No server response was requested.',{operation:action==='open'?'ON':'OFF',ip:result.access_source});
}));
document.querySelector('#install-hint').hidden=!!api?.runtime?.id;
// Remove enrollment secrets before any asynchronous work.
const enrollment=location.hash.startsWith('#import=')?location.href:null;
if(enrollment)history.replaceState(null,'',location.pathname);
await busy(async()=>{if(enrollment)await importProfile(enrollment);else{await load();message.textContent=current?t('Press ON.'):mobile?t('Import your server-issued QR profile.'):t('Import a server-issued JSON profile.');}});
if(!api?.runtime?.id&&'serviceWorker' in navigator)navigator.serviceWorker.register('sw.js').catch(()=>{});

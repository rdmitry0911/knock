import {request,busy,showError,ensurePermission,iceMode,api} from './bridge.js';
import {decodeEnrollment} from './profile-codec.js';
import {bindQRImport} from './qr.js';
import {t,translatePage} from './i18n.js';
translatePage();
const platform=api?.runtime?.getPlatformInfo?await api.runtime.getPlatformInfo():null;
const mobile=platform?.os==='android'||/Android|iPhone|iPad|iPod/i.test(navigator.userAgent)||(navigator.platform==='MacIntel'&&navigator.maxTouchPoints>1);
for(const node of document.querySelectorAll('[data-mobile-only]'))node.hidden=!mobile;
for(const node of document.querySelectorAll('[data-desktop-only]'))node.hidden=mobile;
if(!mobile){document.querySelector('#import-text').placeholder=t('Paste a JSON profile');document.querySelector('#import-details').open=true;}

const message=document.querySelector('#message'),profiles=document.querySelector('#profiles'),form=document.querySelector('#settings-form');
let current=null;
async function load() {
  const value=await request('load');current=value.profile;profiles.replaceChildren();
  for(const profile of value.profiles){const option=new Option(profile.name,profile.key);option.selected=profile.key===value.active;profiles.add(option);}
  document.querySelector('#import-panel').hidden=!!current;document.querySelector('#control-panel').hidden=!current;
  if(!current)return;
  document.querySelector('#server').textContent=current.server_url;
  document.querySelector('#idle').textContent=t('Auto-close after {seconds} s without service traffic.',{seconds:current.settings.idle_timeout});
  form.elements.rules.value=(current.settings.rules??[]).join(',');form.elements.ports.value=current.settings.ports.join(',');form.elements.idle_timeout.value=current.settings.idle_timeout;
  const connection=document.querySelector('#connection-form');connection.elements.transport.value=iceMode(current)?'ice':'https';
  for(const key of ['ice_host','ice_source'])connection.elements[key].value=current[key]??'';
  connection.elements.stun_server.value=current.stun_server??'stun:stun.cloudflare.com:3478';
  document.querySelector('#transport').textContent=iceMode(current)?t('ON/OFF: UDP via WebRTC ICE, without HTTPS requests. Status and settings use HTTPS.'):t('ON/OFF, status and settings use HTTPS.');
}
function showState(response) {
  const state=document.querySelector('#state');
  if(typeof response.access_active==='boolean'){state.textContent=response.access_active?t('Access enabled'):t('Access disabled');state.dataset.active=String(response.access_active);}
  else {state.textContent=t('Sequence sent');delete state.dataset.active;}
  document.querySelector('#rule-details').textContent=Object.entries(response.rules??{}).map(([name,r])=>`${name}: ${r.type} ${r.protocol} ${(r.ports??[r.icmp_type]).join(', ')}${r.dest_ip?' → '+r.dest_ip+(r.dest_port?':'+r.dest_port:''):''}`).join('; ');
  if(response.policy){document.querySelector('#policy').textContent=t('Allowed TCP ports: {ports}. Rules: {rules}. Idle timeout: up to {seconds} s.',{ports:response.policy.allowed_ports.join(', ')||t('none'),rules:(response.policy.allowed_rules??[]).join(', ')||t('none'),seconds:response.policy.max_idle_timeout});form.elements.idle_timeout.max=response.policy.max_idle_timeout;}
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
profiles.addEventListener('change',()=>busy(async()=>{await request('select',{key:profiles.value});await load();document.querySelector('#state').textContent=t('Access not checked');delete document.querySelector('#state').dataset.active;message.textContent=t('Press ON.');}));
for(const action of ['open','close','status'])document.querySelector('#'+action).addEventListener('click',()=>busy(async()=>{
  await ensurePermission(current,action);message.textContent=action==='open'?t('Enabling access…'):action==='close'?t('Disabling access…'):t('Checking…');
  const response=await request(action);showState(response);await load();
  message.textContent=response.transport==='ice'?t('Signed UDP knock {operation} sent. No server response was requested.',{operation:action==='open'?'ON':'OFF'}):response.access_active?t('You can now use the protected service.'):t('Access has been disabled.');
}));
form.addEventListener('submit',event=>{event.preventDefault();busy(async()=>{await ensurePermission(current);const settings={ports:form.elements.ports.value.split(',').filter(p=>p.trim()).map(p=>Number(p.trim())),idle_timeout:Number(form.elements.idle_timeout.value)};if(current.settings.rules!==undefined||form.elements.rules.value.trim())settings.rules=form.elements.rules.value.split(',').map(n=>n.trim()).filter(Boolean);const response=await request('configure',{settings});showState(response);await load();message.textContent=t('Settings saved. Press ON.');});});
document.querySelector('#connection-form').addEventListener('submit',event=>{event.preventDefault();busy(async()=>{const fields=event.target.elements;await request('save-transport',{connection:{transport:fields.transport.value,ice_host:fields.ice_host.value.trim(),ice_source:fields.ice_source.value.trim(),stun_server:fields.stun_server.value.trim()}});await load();message.textContent=t('Connection saved on this device.');});});
document.querySelector('#install-hint').hidden=!!api?.runtime?.id;
// Remove enrollment secrets before any asynchronous work.
const enrollment=location.hash.startsWith('#import=')?location.href:null;
if(enrollment)history.replaceState(null,'',location.pathname);
await busy(async()=>{if(enrollment)await importProfile(enrollment);else{await load();message.textContent=current?t('Press ON.'):mobile?t('Import your server-issued QR profile.'):t('Import a server-issued JSON profile.');}});
if(!api?.runtime?.id&&'serviceWorker' in navigator)navigator.serviceWorker.register('sw.js').catch(()=>{});

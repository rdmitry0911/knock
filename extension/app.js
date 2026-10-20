import {request,busy,showError,ensurePermission,browserMode,iceMode,api} from './bridge.js';
import {decodeEnrollment} from './profile-codec.js';
import {bindQRImport} from './qr.js';
const message=document.querySelector('#message'),profiles=document.querySelector('#profiles'),form=document.querySelector('#settings-form');
let current=null;
async function load() {
  const value=await request('load');current=value.profile;profiles.replaceChildren();
  for(const profile of value.profiles){const option=new Option(profile.name,profile.key);option.selected=profile.key===value.active;profiles.add(option);}
  document.querySelector('#import-panel').hidden=!!current;
  document.querySelector('#control-panel').hidden=!current;
  if(!current)return;
  document.querySelector('#server').textContent=current.server_url;
  document.querySelector('#idle').textContent=`Автоотключение после ${current.settings.idle_timeout} с без трафика к сервису.`;
  form.elements.rules.value=(current.settings.rules??[]).join(',');form.elements.ports.value=current.settings.ports.join(',');form.elements.idle_timeout.value=current.settings.idle_timeout;
  const connection=document.querySelector('#connection-form');
  connection.elements.transport.value=iceMode(current)?'ice':'https';
  for(const key of ['ice_host','ice_source'])connection.elements[key].value=current[key]??'';
  connection.elements.stun_server.value=current.stun_server??'stun:stun.cloudflare.com:3478';
  document.querySelector('#connection-panel').hidden=!browserMode;
  document.querySelector('#transport').textContent=iceMode(current)?'ON/OFF: UDP через WebRTC ICE, без HTTPS-запросов. Статус и настройки требуют HTTPS API.':browserMode?'ON/OFF, статус и настройки: HTTPS API.':'Настольный режим: последовательность передаётся пакетами TCP/UDP.';
}
function showState(response) {
  const state=document.querySelector('#state');
  if(typeof response.access_active==='boolean'){state.textContent=response.access_active?'Доступ включён':'Доступ выключен';state.dataset.active=String(response.access_active);}
  else {state.textContent='Последовательность отправлена';delete state.dataset.active;}
  document.querySelector('#rule-details').textContent=Object.entries(response.rules??{}).map(([name,r])=>`${name}: ${r.type} ${r.protocol} ${(r.ports??[r.icmp_type]).join(', ')}${r.dest_ip?' → '+r.dest_ip+(r.dest_port?':'+r.dest_port:''):''}`).join('; ');
  if(response.policy){document.querySelector('#policy').textContent=`Разрешены TCP-порты ${response.policy.allowed_ports.join(', ')||'нет'}. Правила: ${(response.policy.allowed_rules??[]).join(', ')||'нет'}. Простой — до ${response.policy.max_idle_timeout} с.`;form.elements.idle_timeout.max=response.policy.max_idle_timeout;}
}
async function importProfile(text) {
  const bundle=typeof text==='string'?decodeEnrollment(text):text;
  await request('import',{bundle});await load();
  document.querySelector('#import-text').value='';
  message.textContent='Профиль импортирован. Нажмите ON.';
}
bindQRImport(text=>busy(()=>importProfile(text)),showError);
document.querySelector('#import-file').addEventListener('change',event=>busy(async()=>{const file=event.target.files[0];if(!file||file.size>32768)throw new Error('Выберите файл профиля до 32 КиБ');await importProfile(await file.text());event.target.value='';}));
document.querySelector('#import-button').addEventListener('click',()=>busy(()=>importProfile(document.querySelector('#import-text').value)));
document.querySelector('#add-profile').addEventListener('click',()=>{document.querySelector('#import-panel').hidden=false;document.querySelector('#import-panel').scrollIntoView({behavior:'smooth'});});
profiles.addEventListener('change',()=>busy(async()=>{await request('select',{key:profiles.value});await load();document.querySelector('#state').textContent='Доступ не проверен';delete document.querySelector('#state').dataset.active;message.textContent='Нажмите ON.';}));
for(const action of ['open','close','status'])document.querySelector('#'+action).addEventListener('click',()=>busy(async()=>{
  // Request optional host access directly inside the user's click gesture.
  await ensurePermission(current,action);message.textContent=action==='open'?'Включение доступа…':action==='close'?'Отключение доступа…':'Проверка…';
  let response=await request(action);showState(response);await load();
  if(!browserMode&&action!=='status') {
    await new Promise(resolve=>setTimeout(resolve,200));
    try{response=await request('status');showState(response);}catch{/* Preserve the honest 'sent' state if status is unavailable. */}
  }
  message.textContent=response.message??(response.access_active?'Можно пользоваться защищённым сервисом.':'Разрешение отключено.');
}));
form.addEventListener('submit',event=>{event.preventDefault();busy(async()=>{await ensurePermission(current);const settings={ports:form.elements.ports.value.split(',').filter(p=>p.trim()).map(p=>Number(p.trim())),idle_timeout:Number(form.elements.idle_timeout.value)};if(current.settings.rules!==undefined||form.elements.rules.value.trim())settings.rules=form.elements.rules.value.split(',').map(n=>n.trim()).filter(Boolean);const response=await request('configure',{settings});showState(response);await load();message.textContent='Настройки сохранены. Нажмите ON.';});});
document.querySelector('#transport').textContent=browserMode?'Браузерный режим: последовательность и подтверждение передаются по HTTPS.':'Настольный режим: последовательность передаётся пакетами TCP/UDP.';
document.querySelector('#connection-form').addEventListener('submit',event=>{event.preventDefault();busy(async()=>{const fields=event.target.elements;await request('save-transport',{connection:{transport:fields.transport.value,ice_host:fields.ice_host.value.trim(),ice_source:fields.ice_source.value.trim(),stun_server:fields.stun_server.value.trim()}});await load();message.textContent='Подключение сохранено на этом устройстве.';});});
document.querySelector('#install-hint').hidden=!!api?.runtime?.id;
// Remove the secret fragment from the address/history before any asynchronous work.
const enrollment=location.hash.startsWith('#import=')?location.href:null;
if(enrollment)history.replaceState(null,'',location.pathname);
await busy(async()=>{if(enrollment)await importProfile(enrollment);else{await load();message.textContent=current?'Нажмите ON.':'Импортируйте QR, выданный сервером.';}});
if(!api?.runtime?.id&&'serviceWorker' in navigator)navigator.serviceWorker.register('sw.js').catch(()=>{});

import {bindQRImport} from './qr.js';
import {decodeEnrollment} from './profile-codec.js';
import { request, busy,showError } from './bridge.js';
const form = document.querySelector('#profile');
const message = document.querySelector('#message');
const field = name => form.elements.namedItem(name);
const select = document.querySelector('#profiles');
let current;
function hidePairing() {
  document.querySelector('#pairing-info').hidden = true;
  document.querySelector('#pairing-secret').textContent = '';
  document.querySelector('#pairing-uri').value = '';
}
function display(profile) {
  current = profile;
  hidePairing();
  document.querySelector('#identity').textContent = profile ? `${profile.name} · ${profile.server_url} · ${profile.profile_id}` : 'Нет импортированных профилей';
  if (!profile) return;
  field('public_ip').value = profile.public_ip;
  for (const name of ['ports', 'idle_timeout', 'protocols', 'seq_timeout', 'ip_protection']) {
    const value = profile.settings[name];
    if (field(name).type === 'checkbox') field(name).checked = value;
    else field(name).value = Array.isArray(value) ? value.join(',') : value;
  }
}
async function load() {
  const result = await request('load');
  select.replaceChildren();
  for (const profile of result.profiles) {
    const option = document.createElement('option');
    option.value = profile.key;
    option.textContent = `${profile.name} · ${profile.server_url}`;
    option.selected = profile.key === result.active;
    select.append(option);
  }
  display(result.profile);
  return result;
}
async function refresh() {
  const result = await request('status');
  display(result.profile);
  const policy = result.policy;
  document.querySelector('#policy').textContent = `Разрешённые порты: ${policy.allowed_ports.join(', ')}. Максимальный простой: ${policy.max_idle_timeout} с. ${policy.can_configure ? '' : 'Изменения настроек запрещены администратором.'}`;
  field('idle_timeout').max = policy.max_idle_timeout;
  message.textContent = result.daemon_running ? 'Настройки вашего секрета получены с сервера.' : 'Профиль получен. Служба knockd недоступна; обратитесь к администратору.';
}
document.querySelector('#import-file').addEventListener('change', event => busy(async () => {
  const file = event.target.files[0];
  if (!file) return;
  if (file.size > 32768) throw new Error('Файл подключения слишком большой');
  await request('import', { bundle: JSON.parse(await file.text()) });
  event.target.value = '';
  await load();
  message.textContent = 'Выданный сервером профиль импортирован. Получите его текущие настройки.';
}));
select.addEventListener('change', () => busy(async () => {
  await request('select', { key: select.value });
  await load();
  message.textContent = 'Профиль выбран. Получите настройки с сервера.';
}));
document.querySelector('#refresh').addEventListener('click', () => busy(refresh));
document.querySelector('#save-ip').addEventListener('click', () => busy(async () => {
  await request('save', { public_ip: field('public_ip').value.trim() });
  message.textContent = 'Адрес сохранён локально.';
}));
form.addEventListener('submit', event => {
  event.preventDefault();
  busy(async () => {
    await request('save', { public_ip: field('public_ip').value.trim() });
    const settings = { ports: field('ports').value.split(',').map(p => Number(p.trim())),
      idle_timeout: Number(field('idle_timeout').value), seq_timeout: Number(field('seq_timeout').value),
      protocols: field('protocols').value.split(',').map(p => p.trim().toLowerCase()),
      ip_protection: field('ip_protection').checked };
    const result = await request('configure', { settings });
    display(result.profile);
    message.textContent = 'Настройки этого секрета применены. Для доступа нажмите «Вкл».';
  });
});
document.querySelector('#hide-pairing').addEventListener('click', hidePairing);
document.querySelector('#pairing').addEventListener('click', () => busy(async () => {
  const result = await request('pairing');
  document.querySelector('#pairing-secret').textContent = result.secret;
  document.querySelector('#pairing-uri').value = result.uri;
  document.querySelector('#pairing-info').hidden = false;
}));
await busy(async () => {
  await load();
  message.textContent = current ? 'Профиль загружен. Настройки можно обновить с сервера.' : 'Импортируйте JSON-файл, выданный администратором сервера.';
});

bindQRImport(text=>busy(async()=>{await request('import',{bundle:decodeEnrollment(text)});await load();message.textContent='Профиль из QR импортирован.';}),showError);

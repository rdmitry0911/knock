import { api, request, busy } from './bridge.js';
const message = document.querySelector('#message');
const select = document.querySelector('#profiles');
async function load() {
  const result = await request('load');
  select.replaceChildren();
  for (const profile of result.profiles) {
    const option = document.createElement('option');
    option.value = profile.key;
    option.textContent = profile.name;
    option.selected = profile.key === result.active;
    select.append(option);
  }
  document.querySelector('#server').textContent = result.profile ? `${result.profile.name} · ${result.profile.knock_host}` : 'Импортируйте выданный сервером профиль';
  document.querySelector('#idle').textContent = result.profile ? `Автоотключение после ${result.profile.settings.idle_timeout} с без трафика к защищённому сервису.` : '';
}
for (const action of ['open', 'close', 'status']) {
  document.querySelector('#' + action).addEventListener('click', () => busy(async () => {
    message.textContent = 'Выполняется…';
    const code = document.querySelector('#code').value.trim();
    if (action !== 'status' && code && !/^[0-9]{6}$/.test(code)) throw new Error('Введите 6 цифр из Google Authenticator');
    const response = await request(action, action === 'status' ? {} : { code });
    if (action === 'status') {
      document.querySelector('#state').textContent = response.access_active ? 'Доступ включён' : 'Доступ выключен';
      message.textContent = response.daemon_running ? `Проверено для IP ${response.observed_ip}.` : 'Служба knockd недоступна; обратитесь к администратору.';
      await load();
    } else {
      document.querySelector('#code').value = '';
      document.querySelector('#state').textContent = 'Запрос отправлен';
      message.textContent = response.message;
    }
  }));
}
select.addEventListener('change', () => busy(async () => {
  await request('select', { key: select.value });
  document.querySelector('#state').textContent = 'Доступ не проверен';
  await load();
}));
document.querySelector('#settings').addEventListener('click', () => api.runtime.openOptionsPage());
await busy(load);

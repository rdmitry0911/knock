# Установка расширений и подпись Firefox

В [релизе v3.0.0-r6](https://github.com/rdmitry0911/knock/releases/tag/v3.0.0-r6)
Firefox XPI **ещё не подписаны Mozilla**. Обычная постоянная установка этих файлов
в Firefox будет отклонена. Тестовая установка через `about:debugging` или Android
WebDriver проверяет работу кода, но не заменяет подпись для пользователей.

| Браузер | Как установить текущую сборку |
|---|---|
| Firefox на компьютере | Временно через `about:debugging#/runtime/this-firefox`; постоянно — после получения подписанного Mozilla XPI |
| Firefox Android | Веб-приложение; постоянная установка расширения требует подписанного XPI `firefox-mobile` |
| Chrome/Chromium/Edge на компьютере | Распаковать `knock-control-chromium-browser.zip`, открыть `chrome://extensions` или `edge://extensions`, включить режим разработчика, выбрать «Загрузить распакованное расширение» и папку с `manifest.json` |
| Chrome Android, браузеры iPhone/iPad | Веб-приложение сервера `/app/`, предварительно сохранённое для работы без доступного сайта |

Вариант `firefox-mobile` работает и на компьютере: ICE/HTTPS без локального
помощника. Вариант `firefox` предназначен для настольного Native Messaging;
ему дополнительно нужен помощник из [основной инструкции](../README_RU.md).
Chrome/Edge не устанавливают ZIP как обычное расширение по двойному щелчку.
Для установки из каталога браузера нужна отдельная публикация в магазине.
Распакованную папку сохраняйте на диске; обновляйте её и нажимайте «Обновить»
на странице расширений. См. [инструкцию Chrome](https://developer.chrome.com/docs/extensions/get-started/tutorial/hello-world).

## Получение подписи Mozilla

Подпись можно получить для самостоятельного распространения (**unlisted**):
публиковать расширение в публичном каталоге AMO необязательно. Подпись выдаёт
Mozilla; локальный сертификат и переименование архива её не заменяют.
См. [правила подписи и распространения](https://extensionworkshop.com/documentation/publish/signing-and-distribution-overview/).

Через браузер, без передачи API-ключей:

1. Войдите своим Mozilla-аккаунтом в [AMO Developer Hub](https://addons.mozilla.org/developers/addon/submit/distribution).
2. Выберите распространение **On your own** и загрузите из релиза
   `knock-control-firefox-mobile.unsigned.xpi` (компьютер и Android) или
   `knock-control-firefox.unsigned.xpi` (настольный помощник).
3. Пройдите проверку AMO и скачайте **подписанный результат** со страницы версии.
   Именно этот новый XPI можно устанавливать постоянно и прикладывать к релизу.

Для следующей версии используйте существующую карточку дополнения в AMO.
У двух вариантов разные ID, поэтому они подписываются отдельно.
Подробности — [подача дополнения на подпись](https://extensionworkshop.com/documentation/publish/submitting-an-add-on/).

Автоматически из репозитория:

```sh
# Нужны Node.js, Python 3 и web-ext.
# Задайте WEB_EXT_API_KEY и WEB_EXT_API_SECRET безопасным способом.
./scripts/sign-firefox.sh firefox-mobile
./scripts/sign-firefox.sh firefox
```

Ключи создаются в [AMO API credentials](https://addons.mozilla.org/developers/addon/api/key/).
Не добавляйте их в Git, сообщения или отчёты. Сценарий отправляет код Mozilla
для unlisted-подписи; результат сохраняется в `dist/signed-firefox-mobile`
или `dist/signed-firefox`. Без этих ключей автоматическая подпись недоступна.
Сборка обычных архивов через `package-extension.py` подпись не получает.

## Установка подписанного XPI

На компьютере: `about:addons` → шестерёнка → «Установить дополнение из файла» →
подписанный XPI → подтвердить установку.

На Firefox Android: сохраните подписанный XPI, откройте «Настройки» → «О Firefox»,
пять раз быстро нажмите на логотип Firefox. Вернитесь в настройки, выберите
«Установить расширение из файла» и подписанный XPI. Это включает пункт установки
из файла; требование подписи сохраняется.
Источник: [инструкция Mozilla для компьютера и Android](https://extensionworkshop.com/documentation/publish/install-self-distributed/).

У текущих unlisted-сборок нет собственного сервера автообновлений. Новые
подписанные версии нужно устанавливать вручную с тем же ID дополнения.

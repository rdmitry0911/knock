// Public application shell only. Credentials, QR URLs and API responses are never cached.
const CACHE='knock-control-shell-4.0.3-knock-only';
const FILES=['./','app.html','app.js','bridge.js','browser-client.js','ice-client.js','profile-codec.js','qr.js','i18n.js','ice-operation.js','style.css','vendor/jsQR.js','app.webmanifest','icon.svg','icon-48.png','icon-180.png','icon-192.png','icon-512.png'];
FILES.push(...['en','ru','de','fr','es','pt_BR','zh_CN','ja','ar','hi'].map(locale=>'_locales/'+locale+'/messages.json'));
self.addEventListener('install',event=>{event.waitUntil(caches.open(CACHE).then(cache=>cache.addAll(FILES)).then(()=>self.skipWaiting()));});
self.addEventListener('activate',event=>{event.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(key=>key.startsWith('knock-control-shell-')&&key!==CACHE).map(key=>caches.delete(key)))).then(()=>self.clients.claim()));});
self.addEventListener('fetch',event=>{
  const url=new URL(event.request.url),scope=new URL(self.registration.scope);
  if(event.request.method!=='GET'||url.origin!==scope.origin||!url.pathname.startsWith(scope.pathname)||url.search)return;
  event.respondWith(fetch(event.request).then(response=>{if(response.ok){const copy=response.clone();event.waitUntil(caches.open(CACHE).then(cache=>cache.put(event.request,copy)));}return response;}).catch(async()=>await caches.match(event.request)??Response.error()));
});

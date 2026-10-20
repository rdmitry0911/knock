const integer=(n,min,max,name)=>{if(!Number.isInteger(n)||n<min||n>max)throw new Error(`Некорректное поле ${name}`);return n;};
export function validateBundle(input) {
  if(!input||typeof input!=='object'||input.format!=='knock-control-client-v2')throw new Error('Нужен профиль, выданный сервером Knock Control');
  if(typeof input.profile_id!=='string'||!(/^[a-f0-9]{24}$/).test(input.profile_id))throw new Error('Некорректный ID профиля');
  const url=new URL(input.server_url);
  if(url.protocol!=='https:'||url.username||url.password||!['','/'].includes(url.pathname)||url.search||url.hash)throw new Error('Сервер должен использовать HTTPS');
  if(typeof input.server_certificate_sha256!=='string'||!(/^[a-f0-9]{64}$/).test(input.server_certificate_sha256))throw new Error('Нет отпечатка сертификата сервера');
  const secret=typeof input.secret==='string'?input.secret.replaceAll(' ','').toUpperCase():'';
  if(!(/^[A-Z2-7]{32}$/).test(secret))throw new Error('Некорректный ключ профиля');
  const name=input.name??input.profile_id;
  if(typeof name!=='string'||name.length<1||name.length>80||/[\x00-\x1f]/.test(name))throw new Error('Некорректное имя профиля');
  const host=input.knock_host??url.hostname;
  if(typeof host!=='string'||!(/^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$/).test(host))throw new Error('Некорректный адрес knock-сервера');
  const s=input.settings;
  if(!s||typeof s!=='object'||Array.isArray(s))throw new Error('Нет настроек профиля');
  const ports=s.ports??[22];
  if(!Array.isArray(ports)||(!ports.length&&!Array.isArray(s.rules))||ports.length>15)throw new Error('Нужны TCP-порты или именованные правила');
  const protocols=s.protocols??Array(6).fill('udp');
  if(!Array.isArray(protocols)||protocols.length<3||protocols.length>20||protocols.some(p=>!['tcp','udp'].includes(p)))throw new Error('Некорректная последовательность протоколов');
  const ip=s.ip_protection??true;
  if(typeof ip!=='boolean')throw new Error('Некорректная привязка к IP');
  const config={period:integer(s.period??30,30,30,'period'),base:integer(s.base??20000,1024,65280,'base'),
    idle_timeout:integer(s.idle_timeout??600,10,86400,'idle_timeout'),seq_timeout:integer(s.seq_timeout??10,1,60,'seq_timeout'),
    ports:[...new Set(ports.map(p=>integer(p,1,65535,'port')))].sort((a,b)=>a-b),protocols,ip_protection:ip,profile_id:input.profile_id};
  if(s.rules!==undefined){if(!Array.isArray(s.rules)||s.rules.length>64||new Set(s.rules).size!==s.rules.length||s.rules.some(n=>typeof n!=='string'||!/^[A-Za-z][A-Za-z0-9_]{0,31}$/.test(n)))throw new Error('Некорректный список правил');config.rules=[...s.rules];}
  if(config.ports.some(p=>p>=config.base&&p<=config.base+255)||config.seq_timeout<=protocols.length*.25)throw new Error('Проверьте диапазон портов и таймаут');
  const extra={};
  if(input.ice_version!==undefined)extra.ice_version=integer(input.ice_version,1,1,'ice_version');
  if(input.transport!==undefined){if(!['ice','https'].includes(input.transport))throw new Error('Некорректный транспорт');extra.transport=input.transport;}
  for(const key of ['ice_source','ice_host'])if(input[key]){const ip=input[key];if(typeof ip!=='string'||!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)||ip.split('.').some(n=>Number(n)>255||String(Number(n))!==n))throw new Error('Некорректный IPv4');extra[key]=ip;}
  if(input.stun_server!==undefined){if(typeof input.stun_server!=='string'||!/^stun:[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}:[0-9]{1,5}$/.test(input.stun_server)||Number(input.stun_server.slice(input.stun_server.lastIndexOf(':')+1))<1||Number(input.stun_server.slice(input.stun_server.lastIndexOf(':')+1))>65535)throw new Error('Некорректный STUN-сервер');extra.stun_server=input.stun_server;}
  if(input.last_ice_ms!==undefined)extra.last_ice_ms=integer(input.last_ice_ms,0,Number.MAX_SAFE_INTEGER,'last_ice_ms');
  return {...extra,format:'knock-control-client-v2',profile_id:input.profile_id,name,server_url:url.origin,secret,
    server_certificate_sha256:input.server_certificate_sha256,knock_host:host,settings:config,
    revision:integer(input.revision??1,1,2147483647,'revision'),public_ip:typeof input.public_ip==='string'?input.public_ip:''};
}
export function decodeEnrollment(text) {
  if(typeof text!=='string'||text.length>32768)throw new Error('QR или файл профиля слишком большой');
  text=text.trim();
  if(text.startsWith('{'))return validateBundle(JSON.parse(text));
  if(text.startsWith('otpauth:'))throw new Error('Это ключ Authenticator. Нужен QR полного профиля Knock Control.');
  const url=new URL(text);
  if(url.protocol!=='https:'||url.pathname!=='/app/'||url.username||url.password||url.search)throw new Error('Это не QR подключения Knock Control');
  const tokens=new URLSearchParams(url.hash.slice(1)).getAll('import');
  if(tokens.length!==1||!tokens[0].startsWith('kc2_'))throw new Error('Это не QR подключения Knock Control');
  const token=tokens[0].slice(4);
  if(!(/^[A-Za-z0-9_-]+$/).test(token))throw new Error('Повреждённый QR подключения');
  let compact;
  try {compact=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Uint8Array.from(atob(token.replaceAll('-','+').replaceAll('_','/')),c=>c.charCodeAt(0))));}
  catch {throw new Error('Повреждённый QR подключения');}
  const s=compact.s;
  if(compact.v!==2||!Array.isArray(s)||![6,7].includes(s.length)||typeof s[3]!=='string'||!/^[tu]+$/.test(s[3])||![0,1].includes(s[5]))throw new Error('Неподдерживаемая версия QR');
  const bundle=validateBundle({format:'knock-control-client-v2',profile_id:compact.i,name:compact.n,server_url:compact.u,
    secret:compact.k,server_certificate_sha256:compact.f,knock_host:compact.h,revision:compact.r,...(compact.w!==undefined?{ice_version:compact.w}:{}),
    settings:{base:s[0],ports:s[1],idle_timeout:s[2],protocols:[...s[3]].map(p=>p==='t'?'tcp':'udp'),seq_timeout:s[4],ip_protection:!!s[5],...(s.length===7?{rules:s[6]}:{})}});
  if(url.origin!==bundle.server_url)throw new Error('Адрес QR отличается от сервера профиля');
  return bundle;
}

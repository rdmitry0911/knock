const integer=(n,min,max,name)=>{if(!Number.isInteger(n)||n<min||n>max)throw new Error(`Invalid field ${name}`);return n;};
export function validateBundle(input) {
  if(!input||typeof input!=='object'||!['knock-control-client-v2','knock-control-client-v3'].includes(input.format))throw new Error('A server-issued Knock Control profile is required');
  if(typeof input.profile_id!=='string'||!(/^[a-f0-9]{24}$/).test(input.profile_id))throw new Error('Invalid profile ID');
  const legacy=input.format==='knock-control-client-v2';
  const url=legacy?new URL(input.server_url):null;
  if(legacy&&(url.protocol!=='https:'||url.username||url.password||!['','/'].includes(url.pathname)||url.search||url.hash))throw new Error('Invalid legacy profile URL');
  const secret=typeof input.secret==='string'?input.secret.replaceAll(' ','').toUpperCase():'';
  if(!(/^[A-Z2-7]{32}$/).test(secret))throw new Error('Invalid profile secret');
  const name=input.name??input.profile_id;
  if(typeof name!=='string'||name.length<1||name.length>80||/[\x00-\x1f]/.test(name))throw new Error('Invalid profile name');
  const host=input.knock_host??url?.hostname;
  if(typeof host!=='string'||!(/^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$/).test(host))throw new Error('Invalid knock server address');
  const s=input.settings;
  if(!s||typeof s!=='object'||Array.isArray(s))throw new Error('Missing profile settings');
  const ports=s.ports??[22];
  if(!Array.isArray(ports)||(!ports.length&&!Array.isArray(s.rules))||ports.length>15)throw new Error('TCP ports or named rules are required');
  const protocols=s.protocols??Array(6).fill('udp');
  if(!Array.isArray(protocols)||protocols.length<3||protocols.length>20||protocols.some(p=>!['tcp','udp'].includes(p)))throw new Error('Invalid protocol sequence');
  const ip=s.ip_protection??true;
  if(typeof ip!=='boolean')throw new Error('Invalid IP binding');
  const config={period:integer(s.period??30,30,30,'period'),base:integer(s.base??20000,1024,65280,'base'),
    idle_timeout:integer(s.idle_timeout??600,10,86400,'idle_timeout'),seq_timeout:integer(s.seq_timeout??10,1,60,'seq_timeout'),
    ports:[...new Set(ports.map(p=>integer(p,1,65535,'port')))].sort((a,b)=>a-b),protocols,ip_protection:ip,profile_id:input.profile_id};
  if(s.rules!==undefined){if(!Array.isArray(s.rules)||s.rules.length>64||new Set(s.rules).size!==s.rules.length||s.rules.some(n=>typeof n!=='string'||!/^[A-Za-z][A-Za-z0-9_]{0,31}$/.test(n)))throw new Error('Invalid rule list');config.rules=[...s.rules];}
  if(config.ports.some(p=>p>=config.base&&p<=config.base+255)||config.seq_timeout<=protocols.length*.25)throw new Error('Check the port range and timeout');
  const extra={};
  if(input.ice_version!==undefined)extra.ice_version=integer(input.ice_version,1,1,'ice_version');
  for(const key of ['ice_source','ice_host'])if(input[key]){const ip=input[key];if(typeof ip!=='string'||!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)||ip.split('.').some(n=>Number(n)>255||String(Number(n))!==n))throw new Error('Invalid IPv4 address');extra[key]=ip;}
  if(input.stun_server!==undefined){if(typeof input.stun_server!=='string'||!/^stun:[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}:[0-9]{1,5}$/.test(input.stun_server)||Number(input.stun_server.slice(input.stun_server.lastIndexOf(':')+1))<1||Number(input.stun_server.slice(input.stun_server.lastIndexOf(':')+1))>65535)throw new Error('Invalid STUN server');extra.stun_server=input.stun_server;}
  if(input.last_ice_ms!==undefined)extra.last_ice_ms=integer(input.last_ice_ms,0,Number.MAX_SAFE_INTEGER,'last_ice_ms');
  return {...extra,format:'knock-control-client-v3',profile_id:input.profile_id,name,secret,
    knock_host:host,ice_version:1,settings:config,
    revision:integer(input.revision??1,1,2147483647,'revision'),public_ip:typeof input.public_ip==='string'?input.public_ip:''};
}
export function decodeEnrollment(text) {
  if(typeof text!=='string'||text.length>32768)throw new Error('The QR or profile file is too large');
  text=text.trim();
  if(text.startsWith('{'))return validateBundle(JSON.parse(text));
  if(text.startsWith('otpauth:'))throw new Error('This is an Authenticator secret. Import the complete Knock Control profile QR.');
  const url=new URL(text),modern=/^knock-control:\/\/import\/#/i.test(text);
  if(!modern&&(url.protocol!=='https:'||url.pathname!=='/app/'||url.username||url.password||url.search))throw new Error('This is not a Knock Control enrollment QR');
  if(url.username||url.password||url.search)throw new Error('This is not a Knock Control enrollment QR');
  const tokens=new URLSearchParams(url.hash.slice(1)).getAll('import'),prefix=modern?'kc3_':'kc2_';
  if(tokens.length!==1||!tokens[0].startsWith(prefix))throw new Error('This is not a Knock Control enrollment QR');
  const token=tokens[0].slice(4);
  if(!(/^[A-Za-z0-9_-]+$/).test(token))throw new Error('Invalid enrollment QR');
  let compact;
  try {compact=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Uint8Array.from(atob(token.replaceAll('-','+').replaceAll('_','/')),c=>c.charCodeAt(0))));}
  catch {throw new Error('Invalid enrollment QR');}
  const s=compact.s;
  if(compact.v!==(modern?3:2)||!Array.isArray(s)||![6,7].includes(s.length)||typeof s[3]!=='string'||!/^[tu]+$/.test(s[3])||![0,1].includes(s[5]))throw new Error('Unsupported QR version');
  if(!modern&&url.origin!==compact.u)throw new Error('The QR address does not match the profile server');
  return validateBundle({format:modern?'knock-control-client-v3':'knock-control-client-v2',profile_id:compact.i,name:compact.n,server_url:compact.u,
    secret:compact.k,knock_host:compact.h,revision:compact.r,ice_version:compact.w,
    ...Object.fromEntries(['ice_host','ice_source','stun_server'].filter(k=>compact[k]!==undefined).map(k=>[k,compact[k]])),
    settings:{base:s[0],ports:s[1],idle_timeout:s[2],protocols:[...s[3]].map(p=>p==='t'?'tcp':'udp'),seq_timeout:s[4],ip_protection:!!s[5],...(s.length===7?{rules:s[6]}:{})}});
}

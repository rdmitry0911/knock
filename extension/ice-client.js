// Passive ICE checks: the target does not need to answer or bind a UDP socket.
// RTCPeerConnection runs in the extension transport document or standalone client.
export function ipv4(value) {
  if(typeof value!=='string'||!/^\d{1,3}(\.\d{1,3}){3}$/.test(value))return false;
  return value.split('.').every(n=>String(Number(n))===n&&Number(n)<=255);
}
export function validateStun(value) {
  if(typeof value!=='string'||!/^stun:[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}:[0-9]{1,5}$/.test(value)||Number(value.slice(value.lastIndexOf(':')+1))<1||Number(value.slice(value.lastIndexOf(':')+1))>65535)throw new Error('STUN server format: stun:host:port');
  return value;
}
export async function discoverAccessIPv4() {
  for(const url of ['https://api.ipify.org/?format=json','https://ipv4.icanhazip.com/']) {
    const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),3000);
    try {
      const response=await fetch(url,{cache:'no-store',credentials:'omit',referrerPolicy:'no-referrer',redirect:'error',signal:controller.signal});
      if(!response.ok)continue;
      const raw=(await response.text()).trim(),ip=url.includes('ipify')?JSON.parse(raw).ip:raw;
      if(ipv4(ip)&&Number(ip.split('.')[0])>0&&Number(ip.split('.')[0])<224)return ip;
    } catch {} finally {clearTimeout(timer);}
  }
  throw new Error('Cannot discover the TCP access IPv4. Check Internet access and retry.');
}
export function tcpProofPorts(token,base) {
  const ports=[];
  for(let i=0;i<6;i++) {
    let offset=parseInt(token.slice(101+i*2,103+i*2),16)%255;
    while(ports.includes(base+1+offset))offset=(offset+1)%255;
    ports.push(base+1+offset);
  }
  return ports;
}
export async function sendTcpProof(host,base,token) {
  if(!ipv4(host)||!Number.isInteger(base)||base<1024||base>65280||!/^KNI2[0-9a-f]{24}[OC][0-9a-f]{136}$/.test(token))throw new Error('Invalid TCP knock proof');
  const pending=[];
  // Only TCP SYNs are needed: the ports remain closed and no HTTP response,
  // credentials, TLS exception or extra extension host permission is required.
  for(let pass=0;pass<2;pass++)for(const port of tcpProofPorts(token,base)) {
    const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),650);
    pending.push(fetch(`https://${host}:${port}/`,{method:'HEAD',mode:'cors',credentials:'omit',referrerPolicy:'no-referrer',redirect:'error',cache:'no-store',signal:controller.signal}).catch(()=>{}).finally(()=>clearTimeout(timer)));
    await new Promise(resolve=>setTimeout(resolve,180));
  }
  await Promise.allSettled(pending);
}
export async function sendIce(host,port,token,durationMs=4500,stunServer) {
  if(!ipv4(host)||!Number.isInteger(port)||port<1024||port>65535||(typeof token!=='function'&&(typeof token!=='string'||!/^KNI[12][0-9a-f]{24}[OC][0-9a-f]{136}$/.test(token))))throw new Error('Invalid ICE knock parameters');
  if(typeof RTCPeerConnection!=='function')throw new Error('WebRTC is unavailable in this browser');
  const pc=new RTCPeerConnection({iceServers:stunServer?[{urls:validateStun(stunServer)}]:[],iceTransportPolicy:'all'});
  let timer,channel;
  try {
    let source;
    if(typeof token==='function') {
      source=new Promise((resolve,reject)=>{
        timer=setTimeout(()=>reject(new Error('Cannot discover the public IPv4 via STUN. Ask the administrator for a profile with your public IPv4.')),7000);
        pc.onicecandidate=e=>{const c=e.candidate;if(c?.type==='srflx'&&ipv4(c.address))resolve(c.address);};
      });source.catch(()=>{});
    }
    channel=pc.createDataChannel('knock');const offer=await pc.createOffer();await pc.setLocalDescription(offer);
    if(source){token=await token(await source);clearTimeout(timer);}
    if(typeof token!=='string'||!/^KNI[12][0-9a-f]{24}[OC][0-9a-f]{136}$/.test(token))throw new Error('Invalid ICE knock signature');
    // No ICE password is a profile secret. Authentication is our HMAC token.
    const password=Array.from(crypto.getRandomValues(new Uint8Array(16)),n=>n.toString(16).padStart(2,'0')).join('');
    const fingerprint=Array.from(crypto.getRandomValues(new Uint8Array(32)),n=>n.toString(16).padStart(2,'0').toUpperCase()).join(':');
    const mid=offer.sdp.match(/^a=mid:([^\r\n]+)/m)?.[1]??'0';
    const answer=['v=0','o=- 1 1 IN IP4 0.0.0.0','s=-','t=0 0','a=ice-lite',`a=group:BUNDLE ${mid}`,
      `m=application ${port} UDP/DTLS/SCTP webrtc-datachannel`,`c=IN IP4 ${host}`,`a=mid:${mid}`,
      'a=ice-ufrag:'+token,'a=ice-pwd:'+password,'a=fingerprint:sha-256 '+fingerprint,
      'a=setup:passive','a=sctp-port:5000','a=max-message-size:262144',''].join('\r\n');
    await pc.setRemoteDescription({type:'answer',sdp:answer});
    await pc.addIceCandidate({candidate:`candidate:1 1 UDP 2130706431 ${host} ${port} typ host`,sdpMid:mid,sdpMLineIndex:0,usernameFragment:token});
    await pc.addIceCandidate(null);
    let checking=pc.iceConnectionState!=='new';
    pc.addEventListener('iceconnectionstatechange',()=>{if(pc.iceConnectionState!=='new')checking=true;});
    await new Promise(resolve=>setTimeout(resolve,durationMs));
    if(!checking)throw new Error('ICE knock did not start. Allow WebRTC/UDP.');
  } finally {clearTimeout(timer);channel?.close();pc.close();}
}

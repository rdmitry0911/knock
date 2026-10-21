import {sendIce,ipv4} from './ice-client.js';
import {queuedDispatch} from './browser-client.js';
export async function performIce(operation,code,dispatch=queuedDispatch,key) {
  const {profile,active}=await dispatch({action:'load',key});
  if(!profile)throw new Error('Import a server-issued profile first');
  const host=profile.ice_host||profile.knock_host;
  if(!ipv4(host))throw new Error('Ask the administrator for a profile with the knock server IPv4 address.');
  let proof;
  const sign=async source=>{proof=await dispatch({action:'ice-proof',operation,source,code,key:active});if(!proof.ok)throw new Error(proof.error);return proof.token;};
  const automatic=profile.settings.ip_protection&&!profile.ice_source;
  const token=automatic?sign:await sign(profile.ice_source||'0.0.0.0');
  await sendIce(host,profile.settings.base,token,4500,automatic?(profile.stun_server??'stun:stun.cloudflare.com:3478'):undefined);
  return {ok:true,profile:proof.profile,transport:'ice'};
}

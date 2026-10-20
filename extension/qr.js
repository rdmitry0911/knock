// jsQR is bundled locally; images/camera frames never leave this device.
export async function decodeImage(file) {
  if(!file||file.size>8*1024*1024)throw new Error('Choose a QR image up to 8 MB');
  let source,release=()=>{};
  try {source=await createImageBitmap(file);release=()=>source.close();}
  catch {
    const url=URL.createObjectURL(file);release=()=>URL.revokeObjectURL(url);
    source=await new Promise((resolve,reject)=>{const image=new Image();image.onload=()=>resolve(image);image.onerror=()=>reject(new Error('Cannot read this image'));image.src=url;});
  }
  try {
    const width=source.width||source.naturalWidth,height=source.height||source.naturalHeight;
    const ratio=Math.min(1,1536/Math.max(width,height));
    const canvas=document.createElement('canvas');canvas.width=Math.max(1,Math.round(width*ratio));canvas.height=Math.max(1,Math.round(height*ratio));
    const context=canvas.getContext('2d',{willReadFrequently:true});context.drawImage(source,0,0,canvas.width,canvas.height);
    const pixels=context.getImageData(0,0,canvas.width,canvas.height);
    const code=globalThis.jsQR(pixels.data,pixels.width,pixels.height,{inversionAttempts:'attemptBoth'});
    if(!code?.data)throw new Error('QR not found. Choose a clear, complete image with its white border.');
    return code.data;
  } finally {release();}
}
export function bindQRImport(onImport,onError) {
  const input=document.querySelector('#qr-image'),video=document.querySelector('#qr-video'),panel=document.querySelector('#qr-camera');
  let stream=null,frame=0,stopped=true;
  function stop() {stopped=true;cancelAnimationFrame(frame);stream?.getTracks().forEach(track=>track.stop());stream=null;video.srcObject=null;panel.hidden=true;}
  input?.addEventListener('change',async()=>{try{await onImport(await decodeImage(input.files[0]));}catch(error){onError(error);}finally{input.value='';}});
  document.querySelector('#qr-stop')?.addEventListener('click',stop);
  document.querySelector('#qr-start')?.addEventListener('click',async()=>{
    try {
      stop();
      if(!navigator.mediaDevices?.getUserMedia)throw new Error('Camera unavailable. Import a QR image instead.');
      stream=await navigator.mediaDevices.getUserMedia({video:{facingMode:{ideal:'environment'},width:{ideal:1280}},audio:false});
      video.srcObject=stream;panel.hidden=false;await video.play();stopped=false;
      const canvas=document.createElement('canvas'),context=canvas.getContext('2d',{willReadFrequently:true});let last=0;
      async function scan(now) {
        if(stopped)return;
        if(now-last>250&&video.videoWidth) {
          last=now;const ratio=Math.min(1,960/video.videoWidth);canvas.width=Math.round(video.videoWidth*ratio);canvas.height=Math.round(video.videoHeight*ratio);
          context.drawImage(video,0,0,canvas.width,canvas.height);const image=context.getImageData(0,0,canvas.width,canvas.height);
          const code=globalThis.jsQR(image.data,image.width,image.height,{inversionAttempts:'attemptBoth'});
          if(code?.data){stop();try{await onImport(code.data);}catch(error){onError(error);}return;}
        }
        frame=requestAnimationFrame(scan);
      }
      frame=requestAnimationFrame(scan);
    } catch(error) {stop();onError(error);}
  });
  addEventListener('pagehide',stop);
  document.addEventListener('visibilitychange',()=>{if(document.hidden)stop();});
  return stop;
}

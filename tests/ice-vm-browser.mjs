// Real browser packets through QEMU's UDP WAN forward; no guest API calls.
import http from 'node:http';
import {readFile} from 'node:fs/promises';
import readline from 'node:readline';
import {resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
const pw=await import(process.env.PLAYWRIGHT_MODULE||'playwright');
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const server=http.createServer(async(req,res)=>{
  if(req.url==='/'){res.setHeader('Content-Type','text/html');res.end('<!doctype html><title>ICE transport test</title>');return;}
  const name=req.url.slice(1);
  if(!['ice-client.js','browser-client.js','profile-codec.js'].includes(name)){res.writeHead(404);res.end();return;}
  res.setHeader('Content-Type','text/javascript');res.end(await readFile(resolve(root,'dist/web-app',name)));
});await new Promise(r=>server.listen(0,'127.0.0.1',r));
const browser=await pw[process.argv[2]||'chromium'].launch({headless:true});
try {
  const page=await browser.newPage();await page.goto('http://127.0.0.1:'+server.address().port+'/');
  for await(const line of readline.createInterface({input:process.stdin})) {
    const q=JSON.parse(line);if(q.stop)break;
    const result=await page.evaluate(async q=>{const {makeIceToken}=await import('./browser-client.js'),{sendIce}=await import('./ice-client.js');const token=q.token??await makeIceToken(q.bundle,q.action,q.source??'10.0.2.2');await sendIce(q.host,q.port,token);return {ok:true,token};},q);
    console.log(JSON.stringify(result));
  }
} finally {await browser.close();await new Promise(r=>server.close(r));}

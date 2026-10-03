import http from 'node:http';
import {readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
import {localFeed} from './tools/local-feed.mjs';
import {randomBytes,timingSafeEqual} from 'node:crypto';
const root=new URL('./',import.meta.url);
const routes=new Map([['/','index.html'],['/index.html','index.html'],['/styles.css','styles.css'],['/favicon.svg','favicon.svg'],['/assets/atmosphere-v1.png','assets/atmosphere-v1.png'],['/src/receipts.mjs','src/receipts.mjs'],['/src/receipt-panel.mjs','src/receipt-panel.mjs'],['/src/app.mjs','src/app.mjs'],['/src/model.mjs','src/model.mjs'],['/src/local-access.mjs','src/local-access.mjs'],['/src/demo.mjs','src/demo.mjs'],['/src/guardclaw-report.mjs','src/guardclaw-report.mjs'],['/src/guardclaw-patterns.mjs','src/guardclaw-patterns.mjs'],['/examples/snapshot.json','examples/snapshot.json'],['/examples/empty.json','examples/empty.json']]);
for(const name of ['bricolage-grotesque-latin-wght-normal.woff2','geist-latin-wght-normal.woff2','geist-mono-latin-wght-normal.woff2'])routes.set(`/fonts/${name}`,`fonts/${name}`);
export function createServer({port=4317,live=false,feed=localFeed(),capability}={}){
 if(!Number.isInteger(port)||port<1024||port>65535)throw Error('PORT must be 1024–65535.');
 if(live&&(typeof capability!=='string'||!/^[a-f0-9]{64}$/.test(capability)))throw Error('Live mode requires a fresh launch capability.');
 const expected=live?Buffer.from(capability,'hex'):null;
 // Coalesce reads and cap disk work even when several tabs poll concurrently.
 let cached=null,pending=null,lastRead=0;
 async function readFeed(){
  if(pending)return pending;
  if(Date.now()-lastRead<1000)return cached;
  pending=(async()=>{try{cached=await feed.read();}catch{cached=null;}finally{lastRead=Date.now();pending=null;}return cached;})();
  return pending;
 }
 return http.createServer(async(req,res)=>{
 const headers={
 'Content-Security-Policy':`default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src ${live?"'self'":"'none'"}; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'`,
 'X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','Cache-Control':'no-store',
 'Permissions-Policy':'camera=(), microphone=(), geolocation=()','Cross-Origin-Resource-Policy':'same-origin'
 };
 const host=req.headers.host;
 if(host!==`127.0.0.1:${port}`&&host!==`localhost:${port}`){res.writeHead(403,headers);return res.end('Forbidden host.');}
 if((req.headers.origin&&req.headers.origin!==`http://${host}`)||['cross-site','same-site'].includes(req.headers['sec-fetch-site'])){res.writeHead(403,headers);return res.end('Forbidden origin.');}
 let pathname;try{const url=new URL(req.url,'http://127.0.0.1');if(url.search)throw Error();pathname=url.pathname;}catch{res.writeHead(400,headers);return res.end('Invalid request.');}
 if(pathname==='/api/local-snapshot'&&live){
  // Cross-origin browser callers cannot send this header without a preflight;
  // OPTIONS is rejected above and no CORS permissions are ever returned.
  if(req.headers['x-dot-observatory']!=='local-feed'){res.writeHead(403,headers);return res.end('Explicit local feed request required.');}
  const credential=req.headers['x-dot-observatory-capability'];
  if(typeof credential!=='string'||!/^[a-f0-9]{64}$/.test(credential)||!timingSafeEqual(Buffer.from(credential,'hex'),expected)){res.writeHead(403,headers);return res.end('Local access rejected or expired.');}
 }
 if(req.method!=='GET'&&req.method!=='HEAD'){res.writeHead(405,{...headers,Allow:'GET, HEAD'});return res.end('Read-only server.');}
 if(pathname==='/api/local-snapshot'&&live){
  const data=await readFeed();
  if(data===null){res.writeHead(503,headers);return res.end('Local feed unavailable or invalid. Last displayed snapshot must remain unverified.');}
  res.writeHead(200,{...headers,'Content-Type':'application/json; charset=utf-8'});return res.end(req.method==='HEAD'?undefined:data);
 }
 const file=routes.get(pathname);
 if(!file){res.writeHead(404,headers);return res.end('Not found.');}
 try{let data=await readFile(new URL(file,root));if(live&&file==='index.html')data=Buffer.from(data.toString().replace('data-local-feed="disabled"','data-local-feed="available"'));const type=file.endsWith('.png')?'image/png':file.endsWith('.woff2')?'font/woff2':file.endsWith('.svg')?'image/svg+xml':file.endsWith('.html')?'text/html':file.endsWith('.css')?'text/css':file.endsWith('.json')?'application/json':'text/javascript';res.writeHead(200,{...headers,'Content-Type':(file.endsWith('.woff2')||file.endsWith('.png'))?type:`${type}; charset=utf-8`});res.end(req.method==='HEAD'?undefined:data);}catch{res.writeHead(500,headers);res.end('Unable to read application file.');}
 });
}
export async function startServer({port=4317,live=false,feed=localFeed()}={}){
 if(live)await feed.init();
 const capability=live?randomBytes(32).toString('hex'):undefined;
 const server=createServer({port,live,feed,capability});
 await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,'127.0.0.1',resolve);});
 try{if(live)await feed.publishAccess(capability);}catch{await new Promise(r=>server.close(r));throw Error('Unable to publish owner-only local access file.');}
 // Do not unlink on shutdown: deleting a replaced file would race another launch.
 // This process's capability expires when its listener stops; file is then inert.
 return server;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
const port=Number(process.env.PORT || 4317);
if(process.argv.slice(2).some(x=>x!=='--live')||process.argv.length>3)throw Error('Usage: node server.mjs [--live]');
const live=process.argv.includes('--live');
await startServer({port,live});
console.log(`GuardClaw: http://127.0.0.1:${port}\nServing only public-safe app routes from ${fileURLToPath(root)}\n${live?'Select .observatory-local/access.json in Data & safety, then connect explicitly. One live server per project.':'Local feed disabled.'}\nStop with Ctrl+C.`);
}

import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,realpath,rm,readFile,writeFile,chmod,symlink,link,mkdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {request} from 'node:http';
import {localFeed} from '../tools/local-feed.mjs';
import {createServer,startServer} from '../server.mjs';
import {randomBytes} from 'node:crypto';
import {parseLocalAccess} from '../src/local-access.mjs';
import {MAX_BYTES} from '../src/model.mjs';

const snapshot=()=>({schemaVersion:1,title:'Synthetic transport test',capturedAt:new Date().toISOString().replace(/\.\d{3}Z$/,'Z'),tasks:[],decisions:[],evidence:[]});
async function fixture(t){const root=await realpath(await mkdtemp(join(tmpdir(),'dot-live-test-')));t.after(()=>rm(root,{recursive:true,force:true}));const feed=localFeed(root);await feed.init();return {root,feed,directory:join(root,'.observatory-local'),filename:join(root,'.observatory-local/snapshot.json')};}
test('Atomic validated publication; rejected payloads preserve last good snapshot',async t=>{
 const {feed,filename}=await fixture(t);const safe=snapshot();await feed.publish(JSON.stringify(safe));assert.deepEqual(JSON.parse(await feed.read()),safe);
 const before=await readFile(filename);
 for(const bad of ['{',JSON.stringify({...safe,logs:'untrusted'}),JSON.stringify({...safe,title:'api_key: synthetic-test-value'}),'x'.repeat(MAX_BYTES+1)]){
  await assert.rejects(feed.publish(bad));assert.deepEqual(await readFile(filename),before);
 }
 const replacements=Array.from({length:12},(_,i)=>feed.publish(JSON.stringify({...snapshot(),title:`Synthetic update ${i}`})));
 await Promise.all(replacements);assert.match(JSON.parse(await feed.read()).title,/^Synthetic update \d+$/);
});
test('Reader rejects symlinks, hardlinks, directories, unsafe modes and bounds',async t=>{
 const {feed,root,directory,filename}=await fixture(t);await feed.publish(JSON.stringify(snapshot()));
 await chmod(filename,0o644);await assert.rejects(feed.read());await chmod(filename,0o600);
 await chmod(directory,0o755);await assert.rejects(feed.read());await assert.rejects(feed.init());await chmod(directory,0o700);
 const outside=join(root,'synthetic-other.json');await writeFile(outside,JSON.stringify(snapshot()),{mode:0o600});
 await rm(filename);await symlink(outside,filename);await assert.rejects(feed.read());await rm(filename);
 await link(outside,filename);await assert.rejects(feed.read());await rm(filename);
 await mkdir(filename);await assert.rejects(feed.read());await rm(filename,{recursive:true});
 for(const bytes of [Buffer.alloc(MAX_BYTES+1,32),Buffer.from([0xff]),Buffer.from('{'),Buffer.from(JSON.stringify({...snapshot(),url:'http://127.0.0.1'}))]){
  await writeFile(filename,bytes,{mode:0o600});await assert.rejects(feed.read());
 }
 await rm(directory,{recursive:true});const alternate=join(root,'synthetic-directory');await mkdir(alternate,{mode:0o700});await symlink(alternate,directory);await assert.rejects(feed.init());await assert.rejects(feed.read());
});
async function serve(t,{live,feed}){
 // Kernel chooses a free loopback port; createServer's Host check uses that port.
 const probe=await import('node:net');const reserver=probe.createServer();await new Promise(r=>reserver.listen(0,'127.0.0.1',r));const port=reserver.address().port;await new Promise(r=>reserver.close(r));
 const capability=live?randomBytes(32).toString('hex'):undefined;const server=createServer({port,live,feed,capability});await new Promise((r,j)=>{server.once('error',j);server.listen(port,'127.0.0.1',r);});t.after(()=>new Promise(r=>{server.closeAllConnections();server.close(r);}));return {url:`http://127.0.0.1:${port}`,port,capability};
}
async function get(url,headers={},method='GET'){
 return new Promise((resolve,reject)=>{const req=request(url,{headers,method},res=>{let body='';res.setEncoding('utf8');res.on('data',x=>body+=x);res.on('end',()=>resolve({status:res.statusCode,headers:res.headers,body}));});req.on('error',reject);req.end();});
}
test('Live HTTP surface denies cross-origin access, mutation, paths and remote Host',async t=>{
 const {feed}=await fixture(t);await feed.publish(JSON.stringify(snapshot()));const {url,capability}=await serve(t,{live:true,feed});
 const headers={'X-Dot-Observatory':'local-feed','X-Dot-Observatory-Capability':capability};
 const ok=await get(url+'/api/local-snapshot',headers);assert.equal(ok.status,200);assert.equal(JSON.parse(ok.body).title,'Synthetic transport test');assert.equal(ok.headers['cache-control'],'no-store');assert.equal(ok.headers['access-control-allow-origin'],undefined);
 assert.match((await get(url)).body,/data-local-feed="available"/);
 for(const extra of [{Origin:'https://example.com'},{Origin:'null'},{Host:'example.com'},{'Sec-Fetch-Site':'cross-site'},{'Sec-Fetch-Site':'same-site'}])assert.equal((await get(url+'/api/local-snapshot',{...headers,...extra})).status,403);
 assert.equal((await get(url+'/api/local-snapshot')).status,403);
 assert.equal((await get(url+'/api/local-snapshot',{...headers,Origin:url,'Sec-Fetch-Site':'same-origin'})).status,200);
 for(const method of ['POST','PUT','PATCH','DELETE','OPTIONS'])assert.equal((await get(url+'/api/local-snapshot',headers,method)).status,405);
 assert.equal((await get(url+'/api/local-snapshot?path=/etc/passwd',headers)).status,400);
 for(const path of ['/.observatory-local/snapshot.json','/.observatory-local/access.json','/tools/local-feed.mjs','/server.mjs','/api/publish','/api/local-snapshot/../../etc/passwd','/src/../../private.json'])assert.equal((await get(url+path,headers)).status,404);
 const head=await get(url+'/api/local-snapshot',headers,'HEAD');assert.equal(head.status,200);assert.equal(head.body,'');
});
test('Offline default exposes no feed, retains restrictive CSP and performs no disk reads',async t=>{
 let reads=0;const {url}=await serve(t,{live:false,feed:{read(){reads++;throw Error();}}});
 const root=await get(url);assert.match(root.headers['content-security-policy'],/connect-src 'none'/);assert.match(root.body,/data-local-feed="disabled"/);
 assert.equal((await get(url+'/api/local-snapshot',{'X-Dot-Observatory':'local-feed'})).status,404);assert.equal(reads,0);
});
test('Invalid spool errors disclose no input and bounded caching coalesces concurrent reads',async t=>{
 let reads=0;const {url,capability}=await serve(t,{live:true,feed:{async read(){reads++;await new Promise(r=>setTimeout(r,10));throw Error('PRIVATE synthetic sentinel');}}});
 const results=await Promise.all(Array.from({length:10},()=>get(url+'/api/local-snapshot',{'X-Dot-Observatory':'local-feed','X-Dot-Observatory-Capability':capability})));
 assert.equal(reads,1);for(const r of results){assert.equal(r.status,503);assert.doesNotMatch(r.body,/PRIVATE synthetic sentinel/);}
});

test('Tiny access schema rejects malformed credentials without echoing contents',()=>{
 const capability=randomBytes(32).toString('hex'),text=JSON.stringify({schemaVersion:1,capability});
 assert.ok(parseLocalAccess(Buffer.from(text))===capability);
 for(const bad of [Buffer.concat([Buffer.from([0xef,0xbb,0xbf]),Buffer.from(text)]),text+'\n',text.replace('"schemaVersion":1','"schemaVersion":2'),text.replace(capability,'A'+capability.slice(1)),JSON.stringify({schemaVersion:1,capability,extra:true}),text.replace('"capability":','"capability":"duplicate","capability":'),'{',Buffer.from([0xff]),Buffer.alloc(129)]){
  assert.throws(()=>parseLocalAccess(typeof bad==='string'?Buffer.from(bad):bad));
 }
});
test('Every bad capability rejects before reading or delivering cached snapshots',async t=>{
 let reads=0;const {url,capability}=await serve(t,{live:true,feed:{async read(){reads++;return JSON.stringify(snapshot());}}});
 const valid={'X-Dot-Observatory':'local-feed','X-Dot-Observatory-Capability':capability};
 for(const credential of [undefined,randomBytes(32).toString('hex'),capability.slice(1),'A'+capability.slice(1),capability+', '+capability]){
  const headers={'X-Dot-Observatory':'local-feed'};if(credential!==undefined)headers['X-Dot-Observatory-Capability']=credential;
  for(const method of ['GET','HEAD']){const r=await get(url+'/api/local-snapshot',headers,method);assert.equal(r.status,403);assert.ok(!r.body.includes(capability));}
 }
 assert.equal(reads,0);assert.equal((await get(url+'/api/local-snapshot',valid)).status,200);assert.equal(reads,1);
 assert.equal((await get(url+'/api/local-snapshot',{'X-Dot-Observatory':'local-feed'})).status,403);assert.equal(reads,1);
 const errorServer=await serve(t,{live:true,feed:{async read(){reads++;throw Error();}}});
 assert.equal((await get(errorServer.url+'/api/local-snapshot',valid)).status,403);assert.equal(reads,1);
});
test('Per-launch access is owner-only, unserved, rotated after stop and not changed by failed start',async t=>{
 const {root,feed,directory}=await fixture(t);const address=await serve(t,{live:false,feed});
 const filename=join(directory,'access.json'),original=randomBytes(32).toString('hex');await feed.publishAccess(original);
 await assert.rejects(startServer({port:address.port,live:true,feed}));assert.ok(parseLocalAccess(await readFile(filename))===original);
 // Separate free port only for this disposable project; no existing live instance.
 const probe=await import('node:net');const reserver=probe.createServer();await new Promise(r=>reserver.listen(0,'127.0.0.1',r));const port=reserver.address().port;await new Promise(r=>reserver.close(r));
 const first=await startServer({port,live:true,feed});const firstCapability=parseLocalAccess(await readFile(filename));assert.ok(firstCapability!==original);
 const url=`http://127.0.0.1:${port}`;assert.equal((await get(url+'/.observatory-local/access.json')).status,404);
 assert.equal((await (await import('node:fs/promises')).stat(filename)).mode&0o777,0o600);
 const source=await readFile(new URL('../server.mjs',import.meta.url),'utf8');assert.ok(!source.includes(firstCapability));
 first.closeAllConnections();await new Promise(r=>first.close(r));
 const second=await startServer({port,live:true,feed});t.after(()=>new Promise(r=>{second.closeAllConnections();second.close(r);}));
 const secondCapability=parseLocalAccess(await readFile(filename));assert.ok(secondCapability!==firstCapability);
 assert.equal((await get(url+'/api/local-snapshot',{'X-Dot-Observatory':'local-feed','X-Dot-Observatory-Capability':firstCapability})).status,403);
 assert.equal((await get(url+'/api/local-snapshot',{'X-Dot-Observatory':'local-feed','X-Dot-Observatory-Capability':secondCapability})).status,503);
 // Atomic replacement never follows a substituted access-file symlink/hardlink.
 const target=join(root,'synthetic-target');await writeFile(target,'unchanged',{mode:0o600});await rm(filename);await symlink(target,filename);await feed.publishAccess(randomBytes(32).toString('hex'));assert.equal(await readFile(target,'utf8'),'unchanged');await rm(filename);await link(target,filename);await feed.publishAccess(randomBytes(32).toString('hex'));assert.equal(await readFile(target,'utf8'),'unchanged');
});

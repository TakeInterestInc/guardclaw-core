import {constants} from 'node:fs';
import {lstat, realpath, mkdir, open, rename, unlink} from 'node:fs/promises';
import {resolve, join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {randomUUID} from 'node:crypto';
import {MAX_BYTES, parseSnapshot} from '../src/model.mjs';
import {parseLocalAccess} from '../src/local-access.mjs';

const projectRoot=fileURLToPath(new URL('../', import.meta.url));
const unsafe=()=>{throw Error('Local feed unavailable: initialize the owner-only spool and publish a valid public-safe snapshot.');};

// Only code may choose a project root (tests use temporary projects). HTTP and
// the CLI cannot accept a path. Same-user processes and the project are trusted.
export function localFeed(root=projectRoot){
 const directory=join(resolve(root),'.observatory-local');
 const filename=join(directory,'snapshot.json');
 async function checkDirectory(){
  if(typeof process.getuid!=='function'||!constants.O_NOFOLLOW)unsafe();
  const s=await lstat(directory);
  if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&0o777)!==0o700||await realpath(directory)!==directory)unsafe();
 }
 async function init(){
  if(typeof process.getuid!=='function'||!constants.O_NOFOLLOW)unsafe();
  await mkdir(directory,{mode:0o700}).catch(e=>{if(e.code!=='EEXIST')throw e;});
  await checkDirectory();
 }
 async function read(){
  await checkDirectory();
  // NOFOLLOW blocks symlinks; NONBLOCK prevents a replaced FIFO from hanging.
  const file=await open(filename,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
  try{
   const s=await file.stat();
   if(!s.isFile()||s.nlink!==1||s.uid!==process.getuid()||(s.mode&0o777)!==0o600||s.size>MAX_BYTES)unsafe();
   const buffer=Buffer.alloc(MAX_BYTES+1);
   let size=0;
   while(size<buffer.length){const {bytesRead}=await file.read(buffer,size,buffer.length-size,null);if(!bytesRead)break;size+=bytesRead;}
   if(size>MAX_BYTES)unsafe();
   const text=new TextDecoder('utf-8',{fatal:true}).decode(buffer.subarray(0,size));
   const snapshot=parseSnapshot(text);
   await checkDirectory();
   return JSON.stringify(snapshot);
  }finally{await file.close();}
 }
 async function atomicPublish(name,text){
  await checkDirectory();
  const temporary=join(directory,`publish-${randomUUID()}.tmp`);
  const file=await open(temporary,constants.O_CREAT|constants.O_EXCL|constants.O_WRONLY|constants.O_NOFOLLOW,0o600);
  try{
   await file.writeFile(text);
   await file.sync();
   await file.close();
   await checkDirectory();
   await rename(temporary,join(directory,name));
  }finally{await file.close().catch(()=>{});await unlink(temporary).catch(()=>{});}
 }
 async function publish(text){await atomicPublish('snapshot.json',JSON.stringify(parseSnapshot(text)));}
 async function publishAccess(capability){
  const text=JSON.stringify({schemaVersion:1,capability});
  parseLocalAccess(new TextEncoder().encode(text));
  await atomicPublish('access.json',text);
 }
 return {init,read,publish,publishAccess};
}

if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{
  const feed=localFeed();
  if(process.argv.length!==3)throw Error();
  if(process.argv[2]==='init'){await feed.init();console.log('Owner-only local spool initialized. No agent state was read.');}
  else if(process.argv[2]==='publish'){
   const parts=[];let size=0;
   for await(const chunk of process.stdin){size+=chunk.length;if(size>MAX_BYTES)throw Error();parts.push(chunk);}
   await feed.publish(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(parts)));
   console.log('Public-safe snapshot published locally. Claims remain unverified.');
  }else throw Error();
 }catch{console.error('Local feed rejected. Usage: node tools/local-feed.mjs init | publish < prepared-safe.json. Requires an owner-only initialized spool and valid snapshot v1 (max 256 KiB). No input is echoed.');process.exitCode=1;}
}

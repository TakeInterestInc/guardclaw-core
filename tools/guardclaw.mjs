// Copyright 2026 TakeInterest Inc. SPDX-License-Identifier: Apache-2.0
import {spawnSync} from 'node:child_process';
import {mkdir,lstat,unlink} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {join} from 'node:path';
const root=fileURLToPath(new URL('../',import.meta.url));
const [command,...args]=process.argv.slice(2);
function run(bin,args){const result=spawnSync(bin,args,{cwd:root,stdio:'inherit'});if(result.error||result.status!==0)throw Error(`${bin} failed; use an installed compatible runtime and inspect the output.`);}
async function binaryDirectory({create=false}={}){
 const dir=join(root,'bin');if(create)await mkdir(dir,{recursive:true});
 let stat;try{stat=await lstat(dir);}catch(e){if(!create&&e.code==='ENOENT')return null;throw e;}
 if(!stat.isDirectory()||stat.isSymbolicLink())throw Error('bin must be a real directory.');return dir;
}
async function build(){
 const dir=await binaryDirectory({create:true});
 for(const name of ['guardclaw-scan','guardclaw-report','guardclaw-hook']){
  const destination=join(dir,name);try{const st=await lstat(destination);if(!st.isFile()||st.isSymbolicLink()||st.nlink!==1)throw Error('Existing binary must be a regular unlinked file.');}catch(e){if(e.code!=='ENOENT')throw e;}
  run('go',['build','-trimpath','-o',destination,`./cmd/${name}`]);
 }
}
try{
 if(command==='start'&&(args.length===0||(args.length===1&&args[0]==='--live'))){
  const {startServer}=await import('../observatory/server.mjs');const port=Number(process.env.PORT||4317);const live=args.includes('--live');
  await startServer({port,live});
  console.log(`GuardClaw: http://127.0.0.1:${port}\n${live?'Select observatory/.observatory-local/access.json, then connect explicitly.':'Offline synthetic workspace; local feed disabled.'}\nStop with Ctrl+C. Read docs/SETUP.md before host setup.`);
 }else if(command==='build'&&args.length===0)await build();
 else if(command==='setup'&&args.length===0){
  run(process.execPath,['--version']);run('go',['version']);await build();run(process.execPath,['tools/smoke.mjs']);
  console.log('Local build and synthetic smoke passed. Run npm start. For a supported host, ask your agent to read AGENTS.md and prepare the reviewed preview in docs/SETUP.md. No host settings, accounts or permissions were changed.');
 }else if(command==='clean'&&args.length===0){
  const dir=await binaryDirectory();
  if(dir)for(const name of ['guardclaw-scan','guardclaw-report','guardclaw-hook'])await unlink(join(dir,name)).catch(e=>{if(e.code!=='ENOENT')throw e;});
  console.log('Removed only the three built binaries. Retained policies, previews, receipts and spool; review these before removing them yourself. Remove host handlers first if installed.');
 }else throw Error('Usage: node tools/guardclaw.mjs setup | build | start [--live] | clean');
}catch(error){console.error(error.message);process.exitCode=1;}

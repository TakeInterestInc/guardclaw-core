// Copyright 2026 TakeInterest Inc. SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';import {spawnSync} from 'node:child_process';
import {mkdtemp,writeFile,readFile,rm,access} from 'node:fs/promises';import {tmpdir} from 'node:os';import {join} from 'node:path';import {fileURLToPath} from 'node:url';import net from 'node:net';
import {parseReport} from '../observatory/src/guardclaw-report.mjs';import {verifyReceipts} from '../observatory/src/receipts.mjs';import {createServer} from '../observatory/server.mjs';
const root=fileURLToPath(new URL('../',import.meta.url));const dir=await mkdtemp(join(tmpdir(),'guardclaw-smoke-'));let server;
function run(name,args,input='',expected=0){const r=spawnSync(join(root,'bin',name),args,{input,encoding:'utf8',timeout:15000,maxBuffer:2<<20});assert.equal(r.status,expected,r.stderr);return r.stdout;}
try{
 const policy=join(dir,'policy.json'),journal=join(dir,'receipts.jsonl');
 await writeFile(policy,JSON.stringify({version:1,default:'ask',tools:{mcp__example__send_email:'ask',Read:'allow',mcp__example__delete:'deny'}}),{mode:0o600});
 const args=['--policy',policy,'--receipts',journal];
 const preview=JSON.parse(run('guardclaw-hook',[...args,'--preview','--binary',join(root,'bin','guardclaw-hook')]));assert.equal(Object.keys(preview.hooks).length,3);await assert.rejects(access(journal));
 run('guardclaw-hook',['--policy',policy,'--check-policy']);
 const base={session_id:'synthetic-session',tool_use_id:'synthetic-action',hook_event_name:'PreToolUse',tool_name:'mcp__example__send_email',tool_input:{to:'synthetic@example.invalid',body:'synthetic-body-marker'}};
 assert.equal(JSON.parse(run('guardclaw-hook',args,JSON.stringify(base))).hookSpecificOutput.permissionDecision,'ask');
 assert.deepEqual(JSON.parse(run('guardclaw-hook',args,JSON.stringify({...base,tool_name:'Read',cwd:dir,tool_input:{file_path:join(dir,'synthetic.txt')}}))),{});
 assert.equal(JSON.parse(run('guardclaw-hook',args,JSON.stringify({...base,tool_name:'mcp__example__delete'}))).hookSpecificOutput.permissionDecision,'deny');
 run('guardclaw-hook',args,JSON.stringify({...base,hook_event_name:'PostToolUse',tool_response:'synthetic-private-output'}));
 const content=await readFile(journal);assert.doesNotMatch(content.toString(),/synthetic-body-marker|synthetic@example|synthetic-private-output/);
 const tip=JSON.parse(run('guardclaw-hook',['--verify','--receipts',journal]));const viewed=await verifyReceipts(new Uint8Array(content),tip);assert.equal(viewed.records.length,4);assert.equal(viewed.anchored,true);
 const checkpoint=join(dir,'checkpoint.json');await writeFile(checkpoint,JSON.stringify(tip),{mode:0o600});await writeFile(journal,content.subarray(0,content.indexOf(10)+1));run('guardclaw-hook',['--verify','--receipts',journal,'--checkpoint',checkpoint],'',2);
 const fixture=join(root,'examples','advisory','no-match.txt');run('guardclaw-scan',[fixture]);run('guardclaw-scan',[join(dir,'missing')],'',2);
 const report=run('guardclaw-report',['--snapshot-id','00000000-0000-4000-8000-000000000001','--revision','7'],'Synthetic local description.\n');assert.equal(parseReport(report).outcome,'no_patterns_matched');
 const probe=net.createServer();await new Promise((resolve,reject)=>{probe.once('error',reject);probe.listen(0,'127.0.0.1',resolve);});const port=probe.address().port;await new Promise(r=>probe.close(r));
 server=createServer({port,live:false,feed:{read(){throw Error('Offline mode must never read feed');}}});await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,'127.0.0.1',resolve);});
 const url=`http://127.0.0.1:${port}`;const page=await fetch(url);assert.match(await page.text(),/GuardClaw/);assert.match(page.headers.get('content-security-policy'),/connect-src 'none'/);
 for(const path of ['/src/receipts.mjs','/src/receipt-panel.mjs'])assert.equal((await fetch(url+path)).status,200);
 for(const path of ['/api/local-snapshot','/.guardclaw/receipts.jsonl','/observatory/.observatory-local/access.json','/bin/guardclaw-hook'])assert.equal((await fetch(url+path)).status,404);
 console.log('PASS synthetic build-to-preview, ask/allow/deny responses, metadata receipt chain/browser parity, trusted truncation rejection, original CLI, report contract, offline loopback asset/boundary checks. No tools executed or host settings written.');
}finally{if(server){server.closeAllConnections();await new Promise(r=>server.close(r));}await rm(dir,{recursive:true,force:true});}

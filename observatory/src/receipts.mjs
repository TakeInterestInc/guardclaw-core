// Copyright 2026 TakeInterest Inc. SPDX-License-Identifier: Apache-2.0
// Browser view of the canonical Go metadata journal, never a host authorization.
export const RECEIPT_BYTES=1<<20,RECEIPT_COUNT=2000;
const genesis='0'.repeat(64),hex=/^[a-f0-9]{64}$/,id=/^[a-f0-9]{32}$/,name=/^[A-Za-z0-9_-]{1,128}$/;
const keys=['action_id','chain_id','decision','event','hash','host','outcome','prev_hash','redaction','rule','schema','sequence','timestamp','tool'];
const invalid=()=>{throw Error('Receipt import rejected.');};
function decode(bytes,limit){
 if(!(bytes instanceof Uint8Array)||bytes.length>limit)invalid();
 const text=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes);
 if(text.charCodeAt(0)===0xfeff)invalid();return text;
}
export function canonical(r,withHash=true){
 const sorted=Object.fromEntries(Object.keys(r).sort().filter(k=>withHash||k!=='hash').map(k=>[k,r[k]]));
 return JSON.stringify(sorted).replace(/[<>&\u2028\u2029]/g,c=>'\\u'+c.charCodeAt(0).toString(16).padStart(4,'0'));
}
function validTimestamp(s){
 if(typeof s!=='string'||!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{0,8}[1-9])?Z$/.test(s))return false;
 const base=s.replace(/\.\d+Z$/,'Z'),date=new Date(base);
 return Number.isFinite(date.getTime())&&date.toISOString().replace('.000Z','Z')===base;
}
function valid(r){
 return r&&Object.keys(r).sort().join()===keys.join()&&r.schema==='guardclaw.receipt.v1'&&id.test(r.chain_id)&&hex.test(r.hash)&&hex.test(r.prev_hash)&&
 Number.isSafeInteger(r.sequence)&&r.sequence>0&&validTimestamp(r.timestamp)&&name.test(r.host)&&name.test(r.rule)&&name.test(r.tool)&&
 (id.test(r.action_id)||hex.test(r.action_id))&&r.redaction==='metadata-only.v1'&&
 ((r.event==='decision'&&['allow','deny','ask'].includes(r.decision)&&r.outcome==='pending')||(r.event==='completion'&&r.decision==='none'&&['success','failure'].includes(r.outcome)));
}
export function parseCheckpoint(bytes){
 const text=decode(bytes,512);let r;try{r=JSON.parse(text);}catch{invalid();}
 if(!r||Object.keys(r).sort().join()!=='chain_id,hash,sequence'||!id.test(r.chain_id)||!hex.test(r.hash)||!Number.isSafeInteger(r.sequence)||r.sequence<1)invalid();
 // Checkpoints from the Go CLI can be unsorted and include one final newline.
 // Reject repeated/escaped keys and noninteger tokens via a bounded flat grammar.
 if(!/^\s*\{\s*"(?:chain_id|hash|sequence)"\s*:\s*(?:"[a-f0-9]+"|[1-9][0-9]*)(?:\s*,\s*"(?:chain_id|hash|sequence)"\s*:\s*(?:"[a-f0-9]+"|[1-9][0-9]*)){2}\s*\}\s*$/.test(text)||new Set([...text.matchAll(/"(chain_id|hash|sequence)"\s*:/g)].map(m=>m[1])).size!==3)invalid();
 return r;
}
export async function verifyReceipts(bytes,checkpoint=null){
 const text=decode(bytes,RECEIPT_BYTES);
 if(text&&!text.endsWith('\n'))invalid();
 const lines=text?text.slice(0,-1).split('\n'):[];
 if(lines.length>RECEIPT_COUNT)invalid();
 let previous=genesis,chain=null,anchored=checkpoint===null;const records=[];
 for(const line of lines){
  if(new TextEncoder().encode(line).length+1>8192)invalid();
  let r;try{r=JSON.parse(line);}catch{invalid();}
  if(!valid(r)||canonical(r)!==line||r.sequence!==records.length+1||r.prev_hash!==previous||(chain&&chain!==r.chain_id))invalid();
  const digest=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(canonical(r,false)));
  const hash=[...new Uint8Array(digest)].map(b=>b.toString(16).padStart(2,'0')).join('');
  if(hash!==r.hash)invalid();
  if(checkpoint&&r.sequence===checkpoint.sequence&&r.chain_id===checkpoint.chain_id&&r.hash===checkpoint.hash)anchored=true;
  previous=r.hash;chain=r.chain_id;records.push(r);
 }
 if(!anchored)invalid();
 return {records,checkpoint:records.length?{chain_id:chain,sequence:records.length,hash:previous}:null,anchored:checkpoint!==null};
}

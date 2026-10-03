// Copyright 2026 TakeInterest Inc. SPDX-License-Identifier: Apache-2.0
import {verifyReceipts,parseCheckpoint,RECEIPT_BYTES} from './receipts.mjs';
let journal=null,anchor=null,result=null,message='',generation=0,busy=false;
export function resetReceipts(){busy=false;generation++;journal=null;anchor=null;result=null;message='';}
export function receiptPanel(render){
 const el=(tag,text)=>{const e=document.createElement(tag);if(text)e.textContent=text;return e;};
 const panel=el('section');panel.className='safety-panel';panel.id='receipt-panel';panel.setAttribute('aria-busy',String(busy));
 panel.append(el('h2','Mediated action receipts'),el('p','Open an intentionally selected metadata-only GuardClaw journal. Hash consistency does not authenticate a writer, prove execution or cover tools this adapter did not observe. A retained checkpoint must come from your own trusted record; one supplied alongside an untrusted journal adds no independent trust. Data stays in memory and never changes task checks or permissions.'));
 async function check(nextJournal,nextAnchor,token){
  try{const next=nextJournal?await verifyReceipts(nextJournal,nextAnchor):null;if(token!==generation)return;journal=nextJournal;anchor=nextAnchor;result=next;message=next?(next.anchored?'Chain consistent with selected checkpoint; writer and coverage unverified.':'Chain internally consistent; no trusted checkpoint. Truncation, writer and coverage unverified.'):'Checkpoint selected; choose a journal to check it.';}
  catch{if(token!==generation)return;message='Receipt import rejected. Previous journal and checkpoint preserved; no file content echoed.';}
  if(token===generation){busy=false;render();}
 }
 for(const [type,label,limit] of [['journal','Choose metadata journal',RECEIPT_BYTES],['checkpoint','Choose retained checkpoint',512]]){
  const input=el('input');input.type='file';input.id=`receipt-${type}-file`;input.disabled=busy;input.accept=type==='journal'?'.jsonl,application/x-ndjson':'.json,application/json';
  const l=el('label',label);l.htmlFor=input.id;
  input.addEventListener('change',async()=>{const file=input.files?.[0];if(!file||busy)return;busy=true;panel.setAttribute('aria-busy','true');for(const control of panel.querySelectorAll('input'))control.disabled=true;const token=++generation;try{if(file.size>limit)throw Error();const bytes=new Uint8Array(await file.arrayBuffer());if(token!==generation)return;await check(type==='journal'?bytes:journal,type==='checkpoint'?parseCheckpoint(bytes):anchor,token);}catch{if(token!==generation)return;message='Receipt import rejected. Previous journal and checkpoint preserved; no file content echoed.';busy=false;render();}});
  panel.append(l,input);
 }
 panel.append(el('p','Browser limit: 1 MiB / 2,000 records. For larger journals use bin/guardclaw-hook --verify --receipts /absolute/journal --checkpoint /absolute/trusted-checkpoint from the repository root. Setup and authenticity limits: docs/RECEIPTS.md.'));
 if(message){const status=el('p',message);status.id='receipt-message';status.setAttribute('role','status');panel.append(status);}
 if(result){panel.append(el('p',`${result.records.length} mediated observations; completion records are host-reported outcomes. An ask records a request for approval, not owner approval.`));
  const table=el('table');table.className='evidence-table';const caption=el('caption','Recent metadata observations (last 50)');const head=el('thead'),row=el('tr');for(const title of ['Observed','Tool / host','Decision / outcome']){const th=el('th',title);th.scope='col';row.append(th);}head.append(row);const body=el('tbody');for(const r of result.records.slice(-50)){const tr=el('tr');for(const text of [r.timestamp,`${r.tool} / ${r.host}`,`${r.event}: ${r.decision} / ${r.outcome}`])tr.append(el('td',text));body.append(tr);}table.append(caption,head,body);panel.append(table);
 }
 const remove=el('button','Remove receipt data');remove.type='button';remove.className='secondary';remove.addEventListener('click',()=>{resetReceipts();render();});panel.append(remove);return panel;
}

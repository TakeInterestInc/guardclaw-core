// SPDX-License-Identifier: Apache-2.0
// Port of internal/report/validate.go. See ../../LICENSE and NOTICE.
import {PATTERN_IDS,BASELINE_TREE,LEGACY_PATTERN_IDS,LEGACY_BASELINE_TREE} from './guardclaw-patterns.mjs';
export const REPORT_LIMIT=65536;
const currentIDs=new Set(PATTERN_IDS),legacyIDs=new Set(LEGACY_PATTERN_IDS), uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const errors=new Set(['INVALID_METADATA','INPUT_LIMIT','INVALID_ENCODING','NUL_BYTE','LINE_LIMIT','LINE_COUNT_LIMIT','FINDING_LIMIT','PATTERN_LIMIT','OUTPUT_LIMIT','ENGINE_UNAVAILABLE','ENGINE_RESULT_INVALID','TIMEOUT','CANCELLED','IO_ERROR','NO_CONTENT']);
const invalid=()=>{throw Error('REPORT_INVALID');};
function strictJSON(text){
 let i=0; const ws=()=>{while(/[ \t\r\n]/.test(text[i]||'x'))i++;};
 function string(){if(text[i++]!=='"')invalid();const start=i-1;while(i<text.length){const c=text[i++];if(c==='\\'){i++;continue;}if(c==='"'){try{return JSON.parse(text.slice(start,i));}catch{invalid();}}}invalid();}
 function value(depth){ws();const c=text[i];if(c==='{'||c==='['){if(depth>6)invalid();i++;const obj=c==='{'?Object.create(null):[];const close=c==='{'?'}':']',seen=new Set();ws();if(text[i]===close){i++;return obj;}while(true){ws();if(c==='{'){const key=string();if(seen.has(key))invalid();seen.add(key);ws();if(text[i++]!==':')invalid();obj[key]=value(depth+1);}else obj.push(value(depth+1));ws();const next=text[i++];if(next===close)return obj;if(next!==',')invalid();}}
 if(c==='"')return string();for(const [token,v] of [['null',null],['true',true],['false',false]])if(text.startsWith(token,i)){i+=token.length;return v;}
 const n=/^-?(?:0|[1-9][0-9]*)/.exec(text.slice(i));if(!n)invalid();i+=n[0].length;const v=Number(n[0]);if(!Number.isSafeInteger(v))invalid();return v;}
 const result=value(1);ws();if(i!==text.length)invalid();return result;
}
function object(v,keys){if(!v||typeof v!=='object'||Array.isArray(v)||Object.keys(v).length!==keys.length||keys.some(k=>!Object.hasOwn(v,k)))invalid();}
function subject(v){return !!v&&typeof v.snapshot_id==='string'&&uuid.test(v.snapshot_id)&&Number.isSafeInteger(v.revision)&&v.revision>=0&&!Object.is(v.revision,-0);}
function time(v){if(typeof v!=='string'||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$/.test(v)||v.startsWith('0000'))invalid();const ms=Date.parse(v);if(!Number.isFinite(ms)||new Date(ms).toISOString().slice(0,19)!==v.slice(0,19))invalid();return v.includes('.')?v.slice(0,-1).padEnd(26,'0')+'Z':v.slice(0,-1)+'.000000Z';}
export function validateReport(r){
 object(r,['schema_version','engine','subject','started_at','finished_at','status','outcome','coverage','findings','error']);
 object(r.engine,['module','baseline_tree','mode']);object(r.coverage,['mode','input_bytes','total_lines','scanned_lines','blank_lines']);
 if(r.subject!==null){object(r.subject,['snapshot_id','revision']);if(!subject(r.subject))invalid();}
 if(r.error!==null){object(r.error,['code']);if(!errors.has(r.error.code))invalid();}
 if(r.schema_version!=='guardclaw.scan-report.v1')throw Error('REPORT_UNSUPPORTED');
 if(r.engine.module!=='github.com/TakeInterestInc/guardclaw-core'||![BASELINE_TREE,LEGACY_BASELINE_TREE].includes(r.engine.baseline_tree)||r.engine.mode!=='static_line_scan'||r.coverage.mode!=='all_nonblank_lines_including_comments'||!Array.isArray(r.findings)||r.findings.length>200)invalid();
 const ids=r.engine.baseline_tree===BASELINE_TREE?currentIDs:legacyIDs;
 if(time(r.finished_at)<time(r.started_at))invalid();
 const counts=['input_bytes','total_lines','scanned_lines','blank_lines'].map(k=>r.coverage[k]);
 if(r.status==='failed'){if(r.outcome!=='unknown'||r.findings.length||!r.error||r.error.code==='NO_CONTENT'||(r.subject===null)!==(r.error.code==='INVALID_METADATA')||counts.some(c=>c!==null))invalid();return r;}
 if(!subject(r.subject)||counts.some(c=>!Number.isSafeInteger(c)||c<0))invalid();
 const [bytes,total,scanned,blank]=counts;if(bytes>262144||total>1000||scanned>1000||blank>1000||total!==scanned+blank||bytes<total||(bytes===0)!==(total===0))invalid();
 if(r.status==='no_content'){if(scanned!==0||r.outcome!=='unknown'||r.findings.length||r.error?.code!=='NO_CONTENT')invalid();return r;}
 if(r.status!=='complete'||scanned<1||r.error!==null||r.findings.length>scanned||(r.findings.length===0?r.outcome!=='no_patterns_matched':r.outcome!=='review_needed'))invalid();
 const lines=new Set();for(const f of r.findings){object(f,['line','decision','severity','pattern_ids']);if(!Number.isSafeInteger(f.line)||f.line<1||f.line>total||lines.has(f.line)||!['deny','escalate'].includes(f.decision)||!['critical','high','medium','low','info'].includes(f.severity)||!Array.isArray(f.pattern_ids)||f.pattern_ids.length<1||f.pattern_ids.length>16||new Set(f.pattern_ids).size!==f.pattern_ids.length||f.pattern_ids.some(id=>!ids.has(id)))invalid();lines.add(f.line);}
 return r;
}
export function parseReport(input){
 const bytes=typeof input==='string'?new TextEncoder().encode(input):input;
 if(!(bytes instanceof Uint8Array))invalid();if(bytes.byteLength>REPORT_LIMIT)throw Error('REPORT_TOO_LARGE');
 let text;try{text=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes);}catch{invalid();}
 return validateReport(strictJSON(text));
}
export function assessReport(r,current,now=Date.now()){
 validateReport(r);if(!subject(current))invalid();
 const association=!r.subject?'unattached_error':r.subject.snapshot_id!==current.snapshot_id||r.subject.revision>current.revision?'mismatch_unverified':r.subject.revision<current.revision?'earlier_unverified':'current_unverified';
 const finished=Date.parse(r.finished_at);return {association,provenance:'user_imported_unverified',age:finished>now+300000?'future':now-finished>3600000?'stale':'recent'};
}

import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {parseReport,validateReport,assessReport,REPORT_LIMIT} from '../src/guardclaw-report.mjs';
const root=new URL('../../schemas/',import.meta.url);
const cases=JSON.parse(await readFile(new URL('conformance-cases.json',root),'utf8'));
for(const c of cases.cases)test(`Core conformance: ${c.file}`,async()=>{const bytes=new Uint8Array(await readFile(new URL(c.file,root)));if(c.expected.startsWith('reject')&&c.expected!=='reject_attachment'){assert.throws(()=>parseReport(bytes));return;}const r=parseReport(bytes),a=assessReport(r,cases.attachment_context);if(c.expected==='accept_unattached')assert.equal(a.association,'unattached_error');else if(c.expected==='accept_but_not_current')assert.equal(a.association,'earlier_unverified');else if(c.expected==='reject_attachment')assert.equal(a.association,'mismatch_unverified');else assert.equal(a.association,'current_unverified');assert.equal(a.provenance,'user_imported_unverified');});
const valid=JSON.parse(await readFile(new URL('fixtures/complete-no-match.json',root),'utf8'));
test('Strict integer tokens, UTF-8, BOM, depth, bounds and duplicate escaped keys',()=>{
 const json=JSON.stringify(valid);
 for(const text of [json.replace('"revision":7','"revision":null'),json.replace('"revision":7','"revision":7.0'),json.replace('"revision":7','"revision":7e0'),json.replace('"revision":7','"revision":-0'),json.replace('"revision":7','"revision":9007199254740992'),'\ufeff'+json,json+'{}',json.replace('"schema_version":','"schema_version":"x","schema_vers\\u0069on":'),'{"x":'+ '['.repeat(7)+'0'+']'.repeat(7)+'}'])assert.throws(()=>parseReport(text));
 assert.throws(()=>parseReport(new Uint8Array([0xc3,0x28])));assert.throws(()=>parseReport(' '.repeat(REPORT_LIMIT+1)),/REPORT_TOO_LARGE/);
});
test('Unknown content, URLs and forged engine/pattern identifiers are rejected',()=>{
 for(const patch of [{extra:'<script>fetch("https://example.com")</script>'},{engine:{...valid.engine,mode:'https://example.com'}},{subject:{...valid.subject,snapshot_id:'javascript:alert(1)'}},{findings:[{line:1,decision:'deny',severity:'high',pattern_ids:['<img src=x onerror=alert(1)>']}],outcome:'review_needed'}])assert.throws(()=>validateReport({...structuredClone(valid),...patch}));
});
test('Time validity, future/stale association, exact timestamp order and no authority fields',()=>{
 for(const value of ['0000-01-01T00:00:00Z','2026-02-30T00:00:00Z','2026-01-01T24:00:00Z','2026-01-01T00:00:60Z'])assert.throws(()=>validateReport({...structuredClone(valid),started_at:value}));
 const r={...structuredClone(valid),started_at:'2026-01-01T00:00:00.000002Z',finished_at:'2026-01-01T00:00:00.000001Z'};assert.throws(()=>validateReport(r));
 assert.equal(assessReport(valid,cases.attachment_context,Date.parse(valid.finished_at)+3600001).age,'stale');assert.equal(assessReport(valid,cases.attachment_context,Date.parse(valid.finished_at)-300001).age,'future');assert.equal(assessReport(valid,{...cases.attachment_context,revision:6}).association,'mismatch_unverified');assert.deepEqual(Object.keys(assessReport(valid,cases.attachment_context)).sort(),['age','association','provenance']);
});

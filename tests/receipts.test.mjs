import test from 'node:test';import assert from 'node:assert/strict';import {readFile} from 'node:fs/promises';
import {canonical,verifyReceipts,parseCheckpoint,RECEIPT_BYTES} from '../observatory/src/receipts.mjs';
const bytes=s=>new TextEncoder().encode(s);
const vectors=JSON.parse(await readFile(new URL('../guardian/receipts/testdata/verification-v1.json',import.meta.url)));
for(const v of vectors)test(`Go receipt vector: ${v.name}`,async()=>{if(v.accept)await verifyReceipts(bytes(v.journal),v.checkpoint);else await assert.rejects(()=>verifyReceipts(bytes(v.journal),v.checkpoint));});
const canonicalVectors=JSON.parse(await readFile(new URL('../guardian/receipts/testdata/canonical-v1.json',import.meta.url)));
for(const v of canonicalVectors)test(`Go canonical vector: ${v.name}`,()=>assert.equal(canonical(v.record,false),v.canonical_without_hash));
test('Reject unsafe imports and checkpoints without echoing content',async()=>{
 const good=vectors[0];
 for(const text of [good.journal.replace('"schema":','"private":"raw-synthetic-secret","schema":'),good.journal.replace('"sequence":1','"sequence":1.0'),good.journal.replace('"sequence":1','"sequence":1,"sequence":1'),'\ufeff'+good.journal,good.journal.replace('2026-10-03','2026-02-30'),good.journal.replace('2026-10-03T08:00:00Z','2026-10-03T08:00:00.10Z')])await assert.rejects(()=>verifyReceipts(bytes(text)));
 await assert.rejects(()=>verifyReceipts(new Uint8Array(RECEIPT_BYTES+1)));await assert.rejects(()=>verifyReceipts(new Uint8Array([0xc3,0x28])));
 assert.deepEqual(parseCheckpoint(bytes(JSON.stringify(good.checkpoint)+'\n')),good.checkpoint);
 for(const text of ['{"chain_id":"a","hash":"b","sequence":1}',JSON.stringify({...good.checkpoint,extra:'secret'}),JSON.stringify(good.checkpoint).replace('"sequence":3','"sequence":3.0'),JSON.stringify(good.checkpoint).replace('"sequence":3','"sequence":3,"sequence":3')])assert.throws(()=>parseCheckpoint(bytes(text)));
});

test('Nonstring metadata never passes Go journal semantics after rehashing',async()=>{const original=canonicalVectors[0].record;for(const field of Object.keys(original).filter(k=>k!=='sequence')){const r={...original,[field]:[original[field]]};const hash=await crypto.subtle.digest('SHA-256',bytes(canonical(r,false)));r.hash=[...new Uint8Array(hash)].map(b=>b.toString(16).padStart(2,'0')).join('');if(field==='hash')r.hash=[r.hash];await assert.rejects(()=>verifyReceipts(bytes(canonical(r)+'\n')));}});

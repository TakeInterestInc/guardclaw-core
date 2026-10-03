export const MAX_BYTES = 256 * 1024;
export const STALE_MINUTES = 60;
const fail = message => { throw new Error(message); };
const sensitive = /(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|\b(?:sk|ghp|github_pat|xox[baprs])[-_][A-Za-z0-9_-]{12,}|\bAKIA[A-Z0-9]{16}\b|\bBearer\s+\S+|\b(?:password|api[_ -]?key|access[_ -]?token|secret)\s*[:=]\s*\S+|\b\d{3}-\d{2}-\d{4}\b)/i;
function object(v, keys, required, where) {
  if (!v || typeof v !== 'object' || Array.isArray(v)) fail(`${where}: expected an object.`);
  if (Object.keys(v).some(k => !keys.includes(k))) fail(`${where}: unsupported field. Use only the documented safe schema.`);
  if (required.some(k => !Object.hasOwn(v,k))) fail(`${where}: a required field is missing.`);
}
function string(v, where, max = 600, empty = false) {
  if (typeof v !== 'string' || v.length > max || (!empty && !v.trim())) fail(`${where}: invalid text length.`);
  if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\u202a-\u202e\u2066-\u2069]/.test(v)) fail(`${where}: unsupported control characters.`);
  if (sensitive.test(v)) fail(`${where}: possible sensitive data. Remove credentials and personal identifiers before importing.`);
}
function id(v,where){string(v,where,64);if(!/^[a-zA-Z0-9][a-zA-Z0-9_-]*$/.test(v))fail(`${where}: invalid ID.`);}
function choice(v, values, where) { if(!values.includes(v))fail(`${where}: unsupported value.`); }
function date(v,where,nullable=false) {
  if(nullable && v===null)return;
  if(typeof v!=='string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(v) || !Number.isFinite(Date.parse(v)) || new Date(v).toISOString().replace('.000','')!==v) fail(`${where}: use a valid UTC timestamp (YYYY-MM-DDTHH:mm:ssZ).`);
}
function array(v,where,max=100){if(!Array.isArray(v)||v.length>max)fail(`${where}: expected a bounded array.`);}
function source(v,where){
  object(v,['label','kind','recordId','url'],['label','kind','recordId'],where);
  string(v.label,`${where} label`,120);choice(v.kind,['synthetic','manual','authorized-api'],where);id(v.recordId,`${where} record ID`);
  if(v.url!==undefined){
    string(v.url,`${where} URL`,240);
    let u;try{u=new URL(v.url);}catch{fail(`${where}: invalid source URL.`);}
    const host=u.hostname.toLowerCase();
    if(u.protocol!=='https:' || u.username || u.password || u.search || u.hash || u.port || !/^[a-z0-9.-]+$/.test(host) || !host.includes('.') || /(?:^|\.)(?:localhost|local|internal|test|invalid)$/.test(host) || /^\d+\.\d+\.\d+\.\d+$/.test(host) || /%/.test(u.pathname)) fail(`${where}: source URL must be public HTTPS without credentials, query, fragment, port, IP address, or encoded path.`);
  }
}
function unique(items,where){const ids=new Set();for(const x of items){id(x.id,`${where} ID`);if(ids.has(x.id))fail(`${where}: duplicate ID.`);ids.add(x.id);}return ids;}
export function validateSnapshot(v, now=Date.now()){
  object(v,['schemaVersion','title','capturedAt','tasks','decisions','evidence'],['schemaVersion','title','capturedAt','tasks','decisions','evidence'],'Snapshot');
  if(v.schemaVersion!==1)fail('Unsupported schema version. Expected 1.');
  string(v.title,'Snapshot title',120);date(v.capturedAt,'Capture time');
  const captured=Date.parse(v.capturedAt);if(captured>now+5*60_000)fail('Capture time is in the future.');
  array(v.tasks,'Tasks');array(v.decisions,'Decisions');array(v.evidence,'Evidence',200);
  const taskIds=unique(v.tasks,'Task');unique(v.decisions,'Decision');unique(v.evidence,'Evidence');
  for(const t of v.tasks){
    object(t,['id','title','summary','owner','status','stage','progress','observedAt','source','blocker','nextStep'],['id','title','summary','owner','status','stage','progress','observedAt','source','blocker','nextStep'],'Task');
    string(t.title,'Task title',120);string(t.summary,'Task summary');string(t.owner,'Task owner',80);string(t.nextStep,'Next step');string(t.blocker,'Blocker',600,true);
    choice(t.status,['planned','active','blocked','done','unknown'],'Task status');choice(t.stage,['proposed','implemented','verified'],'Task stage');
    date(t.observedAt,'Task observation',true);source(t.source,'Task source');
    if(t.observedAt && Date.parse(t.observedAt)>captured)fail('Task observation follows capture time.');
    if(t.status==='blocked'&&!t.blocker.trim())fail('A blocked task must state its blocker.');
    if(t.progress!==null){object(t.progress,['completed','total'],['completed','total'],'Progress');if(!Number.isInteger(t.progress.completed)||!Number.isInteger(t.progress.total)||t.progress.total<1||t.progress.total>1000||t.progress.completed<0||t.progress.completed>t.progress.total)fail('Progress must be a valid completed/total checklist.');}
  }
  for(const e of v.evidence){
    object(e,['id','taskId','title','result','observedAt','summary','source'],['id','taskId','title','result','observedAt','summary','source'],'Evidence');
    id(e.taskId,'Evidence task ID');if(!taskIds.has(e.taskId))fail('Evidence refers to an unknown task.');
    string(e.title,'Evidence title',120);string(e.summary,'Evidence summary');choice(e.result,['passed','failed','pending'],'Evidence result');date(e.observedAt,'Evidence observation',true);source(e.source,'Evidence source');
    if(e.observedAt && Date.parse(e.observedAt)>captured)fail('Evidence observation follows capture time.');
    if(e.result!=='pending'&&!e.observedAt)fail('Completed evidence needs an observation time.');
  }
  for(const d of v.decisions){
    object(d,['id','taskId','title','status','recommendation','rationale','tradeoffs','disagreement','outcome','observedAt','source'],['id','taskId','title','status','recommendation','rationale','tradeoffs','disagreement','outcome','observedAt','source'],'Decision');
    id(d.taskId,'Decision task ID');if(!taskIds.has(d.taskId))fail('Decision refers to an unknown task.');
    string(d.title,'Decision title',120);choice(d.status,['awaiting-owner','resolved'],'Decision status');
    for(const key of ['recommendation','rationale','tradeoffs'])string(d[key],`Decision ${key}`);
    for(const key of ['disagreement','outcome'])string(d[key],`Decision ${key}`,600,true);
    date(d.observedAt,'Decision observation',true);source(d.source,'Decision source');
    if(d.observedAt && Date.parse(d.observedAt)>captured)fail('Decision observation follows capture time.');
    if(d.status==='resolved'&&!d.outcome.trim())fail('Resolved decisions require an outcome.');
    if(d.status==='awaiting-owner'&&d.outcome.trim())fail('Pending decisions cannot carry a resolved outcome.');
  }
  for(const t of v.tasks)if(t.stage==='verified'&&!v.evidence.some(e=>e.taskId===t.id&&e.result==='passed'&&e.observedAt))fail('Verified stage needs dated passing evidence for that task.');
  return structuredClone(v);
}
export function parseSnapshot(text,now=Date.now()){
  if(typeof text!=='string'||new TextEncoder().encode(text).length>MAX_BYTES)fail('File exceeds the 256 KiB import limit.');
  let v;try{v=JSON.parse(text);}catch{fail('Invalid JSON. Use the documented snapshot schema.');}
  return validateSnapshot(v,now);
}
export function freshness(observedAt, referenceTime){
  if(!observedAt)return 'unknown';
  const age=(referenceTime-Date.parse(observedAt))/60_000;
  return age<0?'unknown':age>STALE_MINUTES?'stale':'fresh';
}
export function needsAttention(t,snapshot,referenceTime){return t.status==='blocked'||t.status==='unknown'||freshness(t.observedAt,referenceTime)!=='fresh'||snapshot.decisions.some(d=>d.taskId===t.id&&d.status==='awaiting-owner')||snapshot.evidence.some(e=>e.taskId===t.id&&e.result==='failed');}
export function filterTasks(snapshot,{search='',filter='all',referenceTime}){
 return snapshot.tasks.filter(t=>(`${t.title} ${t.summary} ${t.owner} ${t.blocker}`.toLowerCase().includes(search.toLowerCase()))&&(filter==='all'||filter==='attention'&&needsAttention(t,snapshot,referenceTime)||t.stage===filter));
}
export function totals(snapshot){return {tasks:snapshot.tasks.length,blocked:snapshot.tasks.filter(t=>t.status==='blocked').length,decisions:snapshot.decisions.filter(d=>d.status==='awaiting-owner').length,verified:snapshot.tasks.filter(t=>t.stage==='verified').length};}

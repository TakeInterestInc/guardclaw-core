import assert from 'node:assert/strict';import {readFile,mkdir,writeFile} from 'node:fs/promises';import {pathToFileURL} from 'node:url';
const {chromium}=await import(process.env.PLAYWRIGHT_MODULE?pathToFileURL(process.env.PLAYWRIGHT_MODULE).href:'playwright');
const url=process.env.DASHBOARD_URL||'http://127.0.0.1:4317',evidence=process.env.EVIDENCE_DIR||'/tmp/guardclaw-receipt-browser';await mkdir(evidence,{recursive:true});
const vectors=JSON.parse(await readFile(new URL('../guardian/receipts/testdata/verification-v1.json',import.meta.url)));const good=vectors[0],bad=vectors.find(v=>v.name==='tamper');
const browser=await chromium.launch({headless:true}),page=await browser.newPage({viewport:{width:1440,height:1024}});const errors=[],requests=[],checks=[];page.on('pageerror',e=>errors.push(e.message));page.on('console',m=>{if(m.type()==='error')errors.push(m.text());});page.on('request',r=>requests.push(r.url()));
async function check(name,fn){await fn();checks.push({name,result:'passed'});console.log('PASS '+name);}
async function select(id,text){await page.locator(id).setInputFiles({name:'synthetic.json',mimeType:'application/json',buffer:Buffer.from(text)});}
try{
 await page.goto(url);await page.locator('#navigation').getByRole('button',{name:'Data & safety'}).click();
 await check('Page identity and offline receipt controls',async()=>{assert.match(await page.title(),/GuardClaw/);assert.equal(page.url(),url+'/');assert.match(await page.locator('#receipt-panel').textContent(),/Mediated action receipts.*does not authenticate/s);});
 await select('#receipt-journal-file',good.journal);
 await check('Manual canonical journal import is separate and unanchored',async()=>{await page.getByText('Chain internally consistent; no trusted checkpoint. Truncation, writer and coverage unverified.',{exact:true}).waitFor();assert.equal(await page.locator('#receipt-panel tbody tr').count(),3);assert.equal(await page.locator('.metric-value').first().textContent(),'6');});
 await select('#receipt-checkpoint-file',JSON.stringify(good.checkpoint));
 await check('Selected checkpoint checks chain consistency with explicit limits',async()=>{await page.getByText('Chain consistent with selected checkpoint; writer and coverage unverified.',{exact:true}).waitFor();assert.match(await page.locator('#receipt-panel').textContent(),/not owner approval/);});
 await page.locator('#receipt-panel').screenshot({path:evidence+'/desktop-receipts.png'});
 await select('#receipt-journal-file',bad.journal);
 await check('Tampered journal rejected and last good retained without echo',async()=>{await page.getByText('Receipt import rejected. Previous journal and checkpoint preserved; no file content echoed.',{exact:true}).waitFor();assert.equal(await page.locator('#receipt-panel tbody tr').count(),3);});
 await select('#receipt-checkpoint-file',JSON.stringify({...good.checkpoint,hash:'0'.repeat(64)}));
 await check('Wrong checkpoint preserves previous journal and anchor',async()=>{await page.waitForTimeout(100);assert.equal(await page.locator('#receipt-panel tbody tr').count(),3);});
 await page.setViewportSize({width:390,height:844});
 await check('Receipt table fits mobile viewport',async()=>{assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);await page.locator('#receipt-panel').screenshot({path:evidence+'/mobile-receipts.png'});});
 await page.getByRole('button',{name:'Remove receipt data',exact:true}).click();
 await check('Remove/reset/reload discard receipt data',async()=>{assert.equal(await page.locator('#receipt-panel tbody tr').count(),0);await select('#receipt-journal-file',good.journal);await page.waitForFunction(()=>document.querySelectorAll('#receipt-panel tbody tr').length===3);await page.getByRole('button',{name:'Reset demo',exact:true}).first().click();assert.equal(await page.locator('#receipt-panel tbody tr').count(),0);await page.reload();await page.locator('#navigation').getByRole('button',{name:'Data & safety'}).click();assert.equal(await page.locator('#receipt-panel tbody tr').count(),0);});
 if(process.env.AXE_PATH){await page.evaluate(await readFile(process.env.AXE_PATH,'utf8'));await check('Data and receipt controls pass axe',async()=>{const r=await page.evaluate(async()=>window.axe.run(document,{runOnly:{type:'tag',values:['wcag2a','wcag2aa','wcag21aa']}}));assert.deepEqual(r.violations.map(v=>v.id),[]);});}
 await check('No app errors, external requests, upload or persistent storage',async()=>{assert.deepEqual(errors,[]);assert.ok(requests.every(r=>new URL(r).origin===url));assert.equal(await page.evaluate(()=>localStorage.length+sessionStorage.length),0);});
 await writeFile(evidence+'/results.json',JSON.stringify({browser:browser.version(),url,checks,errors,externalRequests:requests.filter(r=>new URL(r).origin!==url).length},null,2));
}finally{await browser.close();}

import {setTimeout} from 'node:timers/promises';
import {localFeed} from './local-feed.mjs';

// A finite authored producer demonstration, never an official host integration.
const feed=localFeed();
const source=recordId=>({label:'Synthetic adapter demo',kind:'synthetic',recordId});
for(let step=1;step<=4;step++){
 const observedAt=new Date().toISOString().replace(/\.\d{3}Z$/,'Z');
 const task={id:'synthetic-build',title:'Synthetic adapter demo',summary:'A synthetic process publishes four authored updates. No real agent session is connected.',owner:'Synthetic producer',status:step===2?'blocked':step===4?'done':'active',stage:step===4?'verified':'implemented',progress:{completed:step,total:4},observedAt,source:source('demo-task'),blocker:step===2?'Synthetic choice awaiting owner review.':'',nextStep:step===4?'Review the reported check; no real command was executed.':'Wait for the next synthetic update.'};
 const decision={id:'synthetic-choice',taskId:task.id,title:'Which synthetic delivery should we illustrate?',status:step>=3?'resolved':'awaiting-owner',recommendation:'Keep the demonstration local.',rationale:'No account or real agent state is needed to exercise the adapter.',tradeoffs:'This proves local transport; actual agent integrations need a supported interface.',disagreement:'',outcome:step>=3?'Authored synthetic outcome: keep it local.':'',observedAt,source:source('demo-decision')};
 const evidence={id:'synthetic-check',taskId:task.id,title:'Illustrative check claim',result:step===4?'passed':'pending',observedAt:step===4?observedAt:null,summary:'Authored synthetic claim, not an executed check, authenticated receipt, or enforcement result.',source:source('demo-check')};
 await feed.publish(JSON.stringify({schemaVersion:1,title:'Synthetic adapter demo',capturedAt:observedAt,tasks:[task],decisions:[decision],evidence:[evidence]}));
 console.log(`Synthetic adapter demo: ${step}/4 published (${task.status}).`);
 if(step<4)await setTimeout(4000);
}

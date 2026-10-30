import { mkdir, readFile, writeFile, open, stat } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { transformJavaScriptWithBlaShield } from '../research/bla/dist/shields/javascript/ast-shield.js';
import { inspectJavaScript, normalizeJavaScript } from '../dist/javascript.js';

// This recorder generates only its own fixture; never accepts target paths or source from callers.
const root=fileURLToPath(new URL('..',import.meta.url));
const runtime=join(root,'.runtime/node-v24.22.1-win-x64/node.exe');
const stamp=new Date().toISOString().replace(/[:.]/g,'-');
const runRoot=join(root,'scratch/javascript',`qualification-${stamp}`);
await mkdir(runRoot,{recursive:true});
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
const commandLog=[];
async function run(executable,args,prefix,{env={},timeout=330000}={}){
  const stdoutPath=prefix+'.stdout',stderrPath=prefix+'.stderr';
  const stdout=await open(stdoutPath,'w'),stderr=await open(stderrPath,'w');
  const start=performance.now();
  const child=spawn(executable,args,{cwd:root,windowsHide:true,stdio:['ignore',stdout.fd,stderr.fd],env:{...process.env,TEMP:join(root,'scratch/providers/temp'),TMP:join(root,'scratch/providers/temp'),...env}});
  let timeoutHit=false;
  const timer=setTimeout(()=>{timeoutHit=true;child.kill();},timeout);
  const outcome=await new Promise(resolve=>{child.on('error',e=>resolve({exitCode:null,error:e.message}));child.on('exit',(code,signal)=>resolve({exitCode:code,signal}));});
  clearTimeout(timer);await stdout.close();await stderr.close();
  const record={executable,args,...outcome,timeoutHit,wallMs:performance.now()-start,stdoutPath,stderrPath,stdoutBytes:(await stat(stdoutPath)).size,stderrBytes:(await stat(stderrPath)).size};
  commandLog.push(record);return record;
}
async function json(path){try{return JSON.parse(await readFile(path,'utf8'));}catch{return null;}}
const source=`export function invoiceStatus(code) {
  if ((code | 0) < 0) return "invoice:rejected";
  if ((code | 0) === 0) return "invoice:pending";
  return "invoice:approved";
}
export function register(router) { router.post("/api/invoice/status", invoiceStatus); }
`;
const task={entryExport:'register',question:'Recover the exact first argument passed to the post call in exported register.',expected:'/api/invoice/status',criterion:'REA semantic call-site argument at index 0 belonging to the register function node; arbitrary literal presence is insufficient'};
async function rea(directory,prefix){
  const command=await run(runtime,[join(root,'research/rea/scripts/rea.mjs'),'analyze-javascript-application',directory,'--format','json'],prefix);
  const result=await json(command.stdoutPath), normalized=result?.normalized_result;
  const graph=normalized?.semantic_graph;
  const functions=graph?.nodes.filter(n=>n.kind==='function'&&n.label==='register').map(n=>n.node_id)??[];
  const matching=graph?.nodes.filter(n=>n.kind==='call-site'&&functions.includes(n.function_node_id)&&n.properties?.arguments?.some(a=>a.index===0&&a.value===task.expected))??[];
  const limits=[];
  const walk=(value,path='')=>{if(!value||typeof value!=='object')return;if(Array.isArray(value)){for(let i=0;i<value.length;i++)walk(value[i],`${path}[${i}]`);return;}for(const [k,v]of Object.entries(value)){if(/resource.?limits?/i.test(k)||k==='limits'&&Array.isArray(v)&&v.length)limits.push({path:path+'.'+k,value:v});else if(k!=='nodes'&&k!=='relations'&&k!=='unknowns'&&k!=='fingerprints')walk(v,path+'.'+k);}};
  walk(normalized);
  return {command,rawStatus:result?.status??result?.code??null,semanticCoverageStatus:graph?.coverage?.status??null,resourceLimits:limits,
    taskRecovered:matching.length===1,matchingCallSites:matching.map(n=>({nodeId:n.node_id,functionNodeId:n.function_node_id,range:n.identity.source_range,argument:n.properties.arguments.find(a=>a.index===0)})),
    statistics:normalized?.statistics??null,rawResultSha256:digest(await readFile(command.stdoutPath)),error:normalized?null:result};
}
const runner=`import { readFile } from 'node:fs/promises';
const file=process.argv[2];
const before=process.resourceUsage();
const subject=await import('./'+file);
const cases=[[-2147483649,'invoice:approved'],[-2147483648,'invoice:rejected'],[-1,'invoice:rejected'],[0,'invoice:pending'],[1,'invoice:approved'],[2147483647,'invoice:approved'],[2147483648,'invoice:rejected'],[4294967296,'invoice:pending'],[0.5,'invoice:pending'],[-0,'invoice:pending'],[NaN,'invoice:pending'],[Infinity,'invoice:pending'],['7','invoice:approved'],[null,'invoice:pending']];
const results=cases.map(([input,expected],index)=>({index,expected,actual:subject.invoiceStatus(input)}));
let calls=[];subject.register({post:(path,handler)=>calls.push({path,handlerSame:handler===subject.invoiceStatus})});
const passed=results.every(r=>r.actual===r.expected)&&calls.length===1&&calls[0].path==='/api/invoice/status'&&calls[0].handlerSame;
const cgroup={};for(const name of ['memory.peak','memory.max','pids.max','cpu.max']){try{cgroup[name]=(await readFile('/sys/fs/cgroup/'+name,'utf8')).trim()}catch{cgroup[name]=null}}
console.log(JSON.stringify({passed,checks:results.length+2,results,calls,resourceUsageBefore:before,resourceUsageAfter:process.resourceUsage(),memoryUsage:process.memoryUsage(),cgroup}));
if(!passed)process.exitCode=1;`;
const image='node@sha256:d862bb5d082c5ae0210ac07e8c0344cb8cf7bef6d78e9b8c50c179da923108ea';
async function dynamic(directory,label,controlledRunner=runner){
  const name='anti-bla-c3-'+randomUUID().slice(0,8);
  const args=['--context','desktop-linux','create','--name',name,'--label','anti-bla.c3-controlled=true','--platform','linux/amd64','--pull','never','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','64','--memory','256m','--cpus','1','--user','65534:65534','--mount',`type=bind,source=${directory},target=/fixture,readonly`,'--workdir','/fixture','--entrypoint','node',image,'/fixture/runner.mjs','index.mjs'];
  await writeFile(join(directory,'runner.mjs'),controlledRunner);
  const prefix=join(runRoot,label+'-docker');
  const create=await run('docker',args,prefix+'-create',{timeout:60000});
  if(create.exitCode!==0)return{status:'UNKNOWN',create};
  try{
    const inspect=await run('docker',['--context','desktop-linux','inspect',name],prefix+'-inspect',{timeout:60000});
    const config=(await json(inspect.stdoutPath))?.[0];
    const verified=config?.HostConfig.NetworkMode==='none'&&config.HostConfig.ReadonlyRootfs===true&&config.Config.User==='65534:65534'&&config.HostConfig.CapDrop?.includes('ALL')&&config.HostConfig.Privileged===false&&!config.HostConfig.CapAdd?.length&&config.HostConfig.SecurityOpt?.includes('no-new-privileges')&&config.HostConfig.Memory===268435456&&config.HostConfig.PidsLimit===64&&config.HostConfig.NanoCpus===1000000000&&config.Mounts.length===1&&config.Mounts[0].RW===false;
    if(!verified)return{status:'UNKNOWN',reason:'containment-inspection-mismatch',create,inspect};
    const execute=await run('docker',['--context','desktop-linux','start','--attach',name],prefix+'-execute',{timeout:60000});
    const observation=await json(execute.stdoutPath);
    const exitInspect=await run('docker',['--context','desktop-linux','inspect',name],prefix+'-exit',{timeout:60000});
    const state=(await json(exitInspect.stdoutPath))?.[0]?.State;
    return{status:execute.exitCode===0&&state?.ExitCode===0&&observation?.passed?'PASS':'FAIL',create,inspect,execute,exitInspect,containerState:state,observation};
  }finally{
    await run('docker',['--context','desktop-linux','rm','--force',name],prefix+'-cleanup',{timeout:60000});
    await run('docker',['--context','desktop-linux','ps','-a','--filter','name=^/'+name+'$','--format','{{.ID}}'],prefix+'-remaining',{timeout:60000});
  }
}
if(process.argv.includes('--review-round1-controls')){
  const digestCollision=await readFile(join(root,'scratch/javascript-review/digest-collision.source.mjs'),'utf8');
  const cases=[
    {name:'R1-digest-collision',ext:'mjs',kind:'plain',source:digestCollision,expected:'changed'},
    {name:'R2-with',ext:'cjs',kind:'with',source:'const x="outer";exports.f=function(o){with(o){return x}}',expected:'inner'},
    {name:'R2-eval',ext:'cjs',kind:'plain',source:'const x="outer";exports.f=function(){eval("var x=\\"inner\\"");return x}',expected:'inner'},
    {name:'R2-with-typeof',ext:'cjs',kind:'with-typeof',source:'function x(){};exports.f=function(o){with(o){return typeof x}}',expected:'number'},
    {name:'R2-eval-typeof',ext:'cjs',kind:'plain',source:'function x(){};exports.f=function(){eval("var x=1");return typeof x}',expected:'number'},
    {name:'R3-if-call',ext:'mjs',kind:'effect',source:'export function f(effect){if((effect()&0)===0)return "yes";return "no"}',expected:{result:'yes',calls:1}},
    {name:'R3-if-getter',ext:'mjs',kind:'getter',source:'export function f(o){if((o.x&0)===0)return "yes";return "no"}',expected:{result:'yes',calls:1}},
    {name:'R4-local-arrow',ext:'mjs',kind:'plain',source:'export function f(){const unused=()=>"DECOY";return "LIVE"}',expected:'LIVE'},
    {name:'R5-reassigned-export',ext:'mjs',kind:'plain',source:'let f=()=>"old";f=()=>"new";export {f}',expected:'new'},
  ];
  const directory=join(runRoot,'review-round1');await mkdir(directory);
  const manifest=[],observations=[];
  for(const control of cases){
    const originalName=control.name+'.'+control.ext,viewName=control.name+'.view.'+control.ext;
    await writeFile(join(directory,originalName),control.source);
    const view=normalizeJavaScript(Buffer.from(control.source),{entryExport:'f',assumeStandardIntrinsics:true});
    if(view.source!==null)await writeFile(join(directory,viewName),view.source);
    const record={name:control.name,sourceSha256:digest(control.source),analysis:view.analysis,changes:view.changes,derivativeAdmitted:view.source!==null,derivativeSha256:view.derivativeSha256};
    const values=view.analysis.facts.filter(f=>f.kind==='return').map(f=>f.value);
    record.staticPassed=control.name.startsWith('R1')?view.analysis.digestProofs.length===0&&values.length===0&&view.changes.length===0:
      control.name.startsWith('R2')||control.name.startsWith('R5')?view.analysis.status==='UNKNOWN'&&values.length===0&&view.source===null:
      control.name==='R3-if-call'?view.analysis.effects.some(f=>f.reason==='unresolved-call-may-have-effects')&&view.changes.length===0:
      control.name==='R3-if-getter'?view.analysis.unknowns.some(f=>f.reason==='reflection-or-accessor')&&view.changes.length===0:
      values.length===1&&values[0]==='LIVE';
    observations.push(record);manifest.push({name:control.name,ext:control.ext,kind:control.kind,expected:control.expected,originalName,viewName:view.source===null?null:viewName});
  }
  await writeFile(join(directory,'manifest.json'),JSON.stringify(manifest));
  const controlledRunner=`import{readFile}from 'node:fs/promises';
const manifest=JSON.parse(await readFile('./manifest.json','utf8'));const records=[];
for(const row of manifest){
 const invoke=async file=>{const module=await import('./'+file);const subject=row.ext==='cjs'?module.default:module;let calls=0;
  if(row.kind==='with')return subject.f({x:'inner'});
  if(row.kind==='with-typeof')return subject.f({x:1});
  if(row.kind==='effect'){const result=subject.f(()=>{calls++;return 9});return {result,calls};}
  if(row.kind==='getter'){const result=subject.f({get x(){calls++;return 9}});return {result,calls};}
  return subject.f();};
 const original=await invoke(row.originalName),derivative=row.viewName===null?null:await invoke(row.viewName);
 records.push({name:row.name,expected:row.expected,original,derivative,derivativeAdmitted:row.viewName!==null,originalMatchesExpected:JSON.stringify(original)===JSON.stringify(row.expected),derivativeMatchesOriginal:row.viewName===null?null:JSON.stringify(derivative)===JSON.stringify(original)});
}
const passed=records.every(r=>r.originalMatchesExpected&&(r.derivativeMatchesOriginal===null||r.derivativeMatchesOriginal));
console.log(JSON.stringify({passed,runtime:process.version,records,resourceUsage:process.resourceUsage()}));if(!passed)process.exitCode=1;`;
  const behavior=await dynamic(directory,'review-round1',controlledRunner);
  const record={schema:'anti-bla.javascript-review-round1-controls/1',at:new Date().toISOString(),sourceOrigin:'Fixed independently authored reviewer controls, copied into a new own fixture directory; original reviewer source and observations retained.',observations,behavior,commandLog,passed:observations.every(r=>r.staticPassed)&&behavior.status==='PASS'};
  const reportPath=join(root,'reports','C3-round1-contained-'+stamp+'.json');await writeFile(reportPath,JSON.stringify(record,null,2));console.log(JSON.stringify({passed:record.passed,staticCases:observations.length,behavior:behavior.status,reportPath}));if(!record.passed)process.exitCode=1;
}else if(process.argv.includes('--qualify-controls')){
  const helpers=Array.from({length:256},(_,i)=>`function helper${i}(x){const n=x|0;return ((n^3)&7)+(n*2)}`).join('\n');
  const choices=Array.from({length:9},(_,i)=>`((flags&${2**i})?${JSON.stringify(String.fromCharCode(97+i))}:${JSON.stringify(String.fromCharCode(65+i))})`).join('+');
  const normal=source+helpers+`\nexport function choose(flags){return ${choices}}`;
  const dir=join(runRoot,'benign-complex');await mkdir(dir);await writeFile(join(dir,'index.mjs'),normal);
  const inspection=inspectJavaScript(Buffer.from(normal),{entryExport:'choose',assumeStandardIntrinsics:true});
  const derivative=normalizeJavaScript(Buffer.from(normal),{entryExport:'choose',assumeStandardIntrinsics:true});
  const controlRea=await rea(dir,join(runRoot,'benign-complex-rea'));
  const controlRunner=`import{choose}from './index.mjs';const cases=[[0,'ABCDEFGHI'],[511,'abcdefghi'],[1,'aBCDEFGHI'],[256,'ABCDEFGHi']];const observations=cases.map(([input,expected])=>({input,expected,actual:choose(input)}));const passed=observations.every(o=>o.actual===o.expected);console.log(JSON.stringify({passed,observations,resourceUsage:process.resourceUsage()}));if(!passed)process.exitCode=1;`;
  const behavior=await dynamic(dir,'benign-complex',controlRunner);
  const malformed=['export function {','export function f(){return '+'!'.repeat(3000)+'true}'];
  const malformedResults=malformed.map(code=>({sha256:digest(code),inspection:inspectJavaScript(Buffer.from(code))}));
  const record={schema:'anti-bla.javascript-controls/1',at:new Date().toISOString(),sourceSha256:digest(normal),sourceBytes:Buffer.byteLength(normal),inspection,derivativeUnchanged:derivative.source===normal,rea:controlRea,behavior,malformedResults,commandLog,passed:inspection.status==='OK'&&inspection.facts.every(f=>f.kind!=='return')&&derivative.source===normal&&controlRea.taskRecovered&&behavior.status==='PASS'&&malformedResults.every(r=>r.inspection.status==='UNKNOWN')};
  await writeFile(join(root,'reports/C3-controls.json'),JSON.stringify(record,null,2));console.log(JSON.stringify({passed:record.passed,nodes:inspection.stats.astNodes,legitimateAlternatives:512,derivativeUnchanged:record.derivativeUnchanged,reaTaskRecovered:controlRea.taskRecovered,behavior:behavior.status}));if(!record.passed)process.exitCode=1;
}else if(process.argv.includes('--verify-existing')){
  const prior=await json(join(root,'reports/C3-qualification.json'));
  if(!prior?.finishedAt||prior.schema!=='anti-bla.javascript-qualification/1'||prior.clean.sha256!==digest(source))throw new Error('Completed controlled qualification record required');
  const files=['src/javascript.ts','src/javascript/evaluator.ts','src/javascript/digest.ts','dist/javascript.js','dist/javascript/evaluator.js','dist/javascript/digest.js','scripts/qualify-javascript.mjs','research/bla/dist/shields/javascript/ast-shield.js','research/rea/scripts/rea.mjs','research/rea/dist/cli.js'];
  const hashes=[];for(const file of files)hashes.push({path:file,sha256:digest(await readFile(join(root,file)))});
  const recordedTaskRecovered=async path=>{
    const raw=await json(path),graph=raw?.normalized_result?.semantic_graph;
    const roots=graph?.nodes.filter(n=>n.kind==='function'&&n.label==='register').map(n=>n.node_id)??[];
    return (graph?.nodes.filter(n=>n.kind==='call-site'&&roots.includes(n.function_node_id)&&n.properties?.arguments?.some(a=>a.index===0&&a.value===task.expected))??[]).length===1;
  };
  const cleanReaTaskRecovered=await recordedTaskRecovered(prior.clean.rea.command.stdoutPath);
  const cleanReaRawSame=digest(await readFile(prior.clean.rea.command.stdoutPath))===prior.clean.rea.rawResultSha256;
  const checks=[];
  for(const row of prior.runs){
    const bytes=await readFile(join(row.protectedRea.command.args[2],'index.mjs'));
    const start=performance.now();const view=normalizeJavaScript(bytes,{assumeStandardIntrinsics:true});
    const wallMs=performance.now()-start;
    checks.push({seed:row.seed,intensity:row.intensity,status:view.analysis.status,wallMs,stats:view.analysis.stats,originalSame:digest(bytes)===row.protectedSha256,derivativeSame:view.derivativeSha256===row.derivativeSha256,protectedReaRawSame:digest(await readFile(row.protectedRea.command.stdoutPath))===row.protectedRea.rawResultSha256,viewReaRawSame:digest(await readFile(row.viewRea.command.stdoutPath))===row.viewRea.rawResultSha256,protectedReaTaskRecovered:await recordedTaskRecovered(row.protectedRea.command.stdoutPath),viewReaTaskRecovered:await recordedTaskRecovered(row.viewRea.command.stdoutPath)});
  }
  const cleanup=await run('docker',['--context','desktop-linux','ps','-a','--filter','label=anti-bla.c3-controlled=true','--format','{{.ID}}'],join(runRoot,'final-cleanup-check'),{timeout:60000});
  const clean=cleanup.exitCode===0&&(await readFile(cleanup.stdoutPath,'utf8')).trim()==='';
  const record={schema:'anti-bla.javascript-revalidation/1',at:new Date().toISOString(),node:process.version,hashes,checks,cleanReaTaskRecovered,cleanReaRawSame,cleanup,ownContainersAbsent:clean,passed:clean&&cleanReaTaskRecovered&&cleanReaRawSame&&checks.length===12&&checks.every(c=>c.status==='OK'&&c.originalSame&&c.derivativeSame&&c.protectedReaRawSame&&c.viewReaRawSame&&!c.protectedReaTaskRecovered&&c.viewReaTaskRecovered),note:'Current implementation reproduces the exact bytes previously qualified by the pinned REA and contained behavior runs. Exact call-site task results are recomputed from preserved raw REA output. Raw REA evidence is reused only for byte-identical artifacts; no new timing or provider invocation is attributed to those earlier runs.'};
  await writeFile(join(root,'reports/C3-revalidation.json'),JSON.stringify(record,null,2));console.log(JSON.stringify({passed:record.passed,checks:checks.length,ownContainersAbsent:clean}));if(!record.passed)process.exitCode=1;
}else if(process.argv.includes('--replay-controlled-dynamic')){
  const reportPath=join(root,'reports/C3-qualification.json');
  const prior=await json(reportPath);
  if(!prior?.finishedAt||prior.schema!=='anti-bla.javascript-qualification/1'||prior.clean.sha256!==digest(source))throw new Error('Completed controlled qualification record required');
  await writeFile(join(runRoot,'prior-report.json'),JSON.stringify(prior,null,2));
  const expectedRoot=resolve(root,'scratch/javascript');
  const checkedDirectory=async(record,expected)=>{const directory=resolve(record.command.args[2]);if(!directory.startsWith(expectedRoot+'\\')&&!directory.startsWith(expectedRoot+'/'))throw new Error('Controlled path outside own fixture tree');if(digest(await readFile(join(directory,'index.mjs')))!==expected)throw new Error('Controlled fixture changed');return directory;};
  prior.rejectedDynamicAttempts={clean:prior.clean.dynamic,runs:prior.runs.map(r=>({seed:r.seed,intensity:r.intensity,protected:r.protectedDynamic,view:r.viewDynamic}))};
  prior.clean.dynamic=await dynamic(await checkedDirectory(prior.clean.rea,prior.clean.sha256),'clean-replay');
  for(const row of prior.runs){const label=row.intensity+'-'+row.seed.at(-1);console.log(JSON.stringify({progress:'dynamic-replay',label}));row.protectedDynamic=await dynamic(await checkedDirectory(row.protectedRea,row.protectedSha256),label+'-protected-replay');row.viewDynamic=await dynamic(await checkedDirectory(row.viewRea,row.derivativeSha256),label+'-view-replay');await writeFile(reportPath,JSON.stringify(prior,null,2));}
  prior.commandLog.push(...commandLog);prior.dynamicRecorderNode=process.version;prior.claims.businessOutput=prior.clean.dynamic.status==='PASS'&&prior.runs.every(r=>r.protectedDynamic.status==='PASS'&&r.viewDynamic.status==='PASS')?'PASS':'UNKNOWN';prior.finishedAt=new Date().toISOString();
  await writeFile(reportPath,JSON.stringify(prior,null,2));await writeFile(join(runRoot,'report.json'),JSON.stringify(prior,null,2));console.log(JSON.stringify({summary:prior.summary,claims:prior.claims}));
  process.exitCode=prior.claims.businessOutput==='PASS'?0:1;
}else{
const cleanDir=join(runRoot,'clean');await mkdir(cleanDir);await writeFile(join(cleanDir,'index.mjs'),source);
const clean=await rea(cleanDir,join(runRoot,'clean-rea'));const cleanDynamic=await dynamic(cleanDir,'clean');
const report={schema:'anti-bla.javascript-qualification/1',startedAt:stamp,sourceOrigin:'Independently authored controlled invoice fixture; implementation-source-informed white-box research, no upstream tests/challenge read.',
  toolchain:{bla:{commit:'b2d643600774d62e562081129e55b13b0d9e8a80',version:'1.5.1',entry:'research/bla/dist/shields/javascript/ast-shield.js#transformJavaScriptWithBlaShield'},rea:{commit:'317bf3fe235e655b2d752d3be261cc0da7d00f2b',version:'6.8.0',entry:'research/rea/scripts/rea.mjs',limits:'Original defaults; no budget overrides.'},node:process.version,dockerImage:image},
  task,clean:{sha256:digest(source),rea:clean,dynamic:cleanDynamic},runs:[],commandLog,claims:{analysisView:'UNKNOWN',businessOutput:'UNKNOWN',fullEquivalence:'UNKNOWN',comprehensiveC3:'UNKNOWN'},limitations:['Only independently authored fixture family is qualified; no universal semantic recovery claim.','REA coverage/status/limits remain raw even when the specified call argument is recovered.','No original symbol restoration, arbitrary reflection/getters, runtime/memory bypass or full execution equivalence.'],rejectedAttempts:['Initial minimal digest test used an incorrect placeholder expected value, corrected before implementation using an independent unsigned BigInt calculation; both RED logs retained.','Initial probe used exported dist/cli.js rather than executable REA wrapper and produced no evidence; not counted.']};
const seeds=['c3-heldout-cedar-20261030-a','c3-heldout-lotus-20261030-b','c3-heldout-fern-20261030-c'];
for(const intensity of ['stealth','balanced','maximum','bankrupt'])for(const seed of seeds){
  const label=intensity+'-'+seed.at(-1);console.log(JSON.stringify({progress:'start',label}));
  const generated=transformJavaScriptWithBlaShield(source,{seed,intensity,filename:'index.mjs',enableRuntimeShield:true});
  const protectedDir=join(runRoot,label+'-protected'),viewDir=join(runRoot,label+'-view');await mkdir(protectedDir);await mkdir(viewDir);
  const original=Buffer.from(generated.code);await writeFile(join(protectedDir,'index.mjs'),original);
  const started=performance.now(),usageBefore=process.resourceUsage(),view=normalizeJavaScript(original,{assumeStandardIntrinsics:true});
  const antiBla={status:view.analysis.status,wallMs:performance.now()-started,processUsageBefore:usageBefore,processUsageAfter:process.resourceUsage(),stats:view.analysis.stats,digestProofs:view.analysis.digestProofs,changes:view.changes,facts:view.analysis.facts,unknowns:view.analysis.unknowns,effects:view.analysis.effects,assumptions:view.analysis.assumptions};
  const derivativeSource=view.source??generated.code;
  await writeFile(join(viewDir,'index.mjs'),derivativeSource);
  const protectedRea=await rea(protectedDir,join(runRoot,label+'-protected-rea'));
  const viewRea=await rea(viewDir,join(runRoot,label+'-view-rea'));
  const protectedDynamic=await dynamic(protectedDir,label+'-protected'),viewDynamic=await dynamic(viewDir,label+'-view');
  const unchanged=digest(await readFile(join(protectedDir,'index.mjs')))===digest(original);
  const row={seed,intensity,enableRuntimeShield:true,sourceSha256:digest(source),protectedSha256:digest(original),derivativeSha256:digest(derivativeSource),protectedBytes:original.length,derivativeBytes:Buffer.byteLength(derivativeSource),derivativeAdmitted:view.source!==null,originalUnchanged:unchanged,
    generation:{carrierType:generated.carrierType,loader:generated.loader,exportedSymbols:generated.exportedSymbols,decoyFunctionsInjected:generated.decoyFunctionsInjected,primitiveCandidateBranchesCreated:generated.primitiveCandidateBranchesCreated,aliasSelectionStatesCreated:generated.aliasSelectionStatesCreated},antiBla,protectedRea,viewRea,protectedDynamic,viewDynamic,
    taskStatus:clean.taskRecovered&&view.source!==null&&viewRea.taskRecovered&&unchanged?'RECOVERED':'UNKNOWN',measuredDelta:clean.taskRecovered&&view.source!==null&&!protectedRea.taskRecovered&&viewRea.taskRecovered};
  report.runs.push(row);await writeFile(join(root,'reports/C3-qualification.json'),JSON.stringify(report,null,2));
  console.log(JSON.stringify({progress:'complete',label,bytes:original.length,nodes:antiBla.stats.astNodes,changes:antiBla.changes.length,antiBla:antiBla.status,protectedRecovered:protectedRea.taskRecovered,viewRecovered:viewRea.taskRecovered,dynamic:[protectedDynamic.status,viewDynamic.status]}));
}
report.claims.analysisView=report.runs.every(r=>r.taskStatus==='RECOVERED')?'PASS':'CONDITIONAL';
report.claims.businessOutput=cleanDynamic.status==='PASS'&&report.runs.every(r=>r.protectedDynamic.status==='PASS'&&r.viewDynamic.status==='PASS')?'PASS':'UNKNOWN';
report.finishedAt=new Date().toISOString();report.summary={runs:report.runs.length,recovered:report.runs.filter(r=>r.taskStatus==='RECOVERED').length,measuredDeltas:report.runs.filter(r=>r.measuredDelta).length,originalsUnchanged:report.runs.every(r=>r.originalUnchanged)};
await writeFile(join(root,'reports/C3-qualification.json'),JSON.stringify(report,null,2));await writeFile(join(runRoot,'report.json'),JSON.stringify(report,null,2));
console.log(JSON.stringify({summary:report.summary,claims:report.claims,report:join(root,'reports/C3-qualification.json')}));
if(report.claims.analysisView!=='PASS'||report.claims.businessOutput!=='PASS')process.exitCode=1;
}

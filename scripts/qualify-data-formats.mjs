import { readFileSync,writeFileSync,mkdirSync,existsSync } from 'node:fs';
import { resolve,join } from 'node:path';
import { createHash,randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { performance } from 'node:perf_hooks';
import { DatabaseSync } from 'node:sqlite';
import { inspectWasm,inspectSqlite,inspectModel } from '../dist/formats/index.js';
import { protectWasmBinary } from '../research/bla/dist/shields/formats/wasm.js';
import { protectSqliteBuffer } from '../research/bla/dist/shields/formats/sqlite.js';
import { protectSafetensorsBuffer,protectGgufBuffer } from '../research/bla/dist/shields/formats/model.js';

const root=resolve(import.meta.dirname,'..'),node=process.execPath,dir=join(root,'scratch/data-formats/qualification-'+new Date().toISOString().replaceAll(':','-'));
mkdirSync(dir,{recursive:true});mkdirSync(join(root,'reports'),{recursive:true});
const ownedTemp=join(dir,'temp');mkdirSync(ownedTemp,{recursive:true});process.env.TEMP=ownedTemp;process.env.TMP=ownedTemp;
const digest=b=>createHash('sha256').update(b).digest('hex');
const records=[],commands=[],seeds=['c6-independent-713','c6-independent-819','c6-independent-927'];
const report={schema:'anti-bla.c6-data/1',started:new Date().toISOString(),status:'RUNNING',audit_source:'implementation-worker',
  pinned:{bla:'b2d643600774d62e562081129e55b13b0d9e8a80',bla_version:'1.5.1',rea:'317bf3fe235e655b2d752d3be261cc0da7d00f2b',rea_version:'6.8.0',node:process.version},
  scope:'Actual emitter three-seed bounded selected export/stored-record/tensor recovery; whole-artifact equivalence UNKNOWN; independent review pending',records,commands};
function command(executable,args,timeout=60000){const t=performance.now(),p=spawnSync(executable,args,{cwd:root,encoding:'utf8',timeout,maxBuffer:16*1024*1024,windowsHide:true});
  const r={executable,args,exit:p.status,signal:p.signal,error:p.error?.message??null,elapsed_ms:performance.now()-t,stdout:p.stdout??'',stderr:p.stderr??'',peak_rss:null};commands.push(r);return r;}
const actualBla=command('git',['-C','research/bla','rev-parse','HEAD']),actualRea=command('git',['-C','research/rea','rev-parse','HEAD']);
if(actualBla.stdout.trim()!==report.pinned.bla||actualRea.stdout.trim()!==report.pinned.rea)throw new Error('pinned source identity mismatch');
function rea(path,kind,extra=[]){return command(node,[join(root,'research/rea/scripts/rea.mjs'),kind,path,...extra,'--format','json','--full-output',...(kind==='inspect-wasm-artifact'?['--filter-output','provider,normalized_result.validation,normalized_result.interface.state,normalized_result.interface.issues,normalized_result.wat.sha256,normalized_result.runtime_execution,normalized_result.tool_profile.output_budget_bytes']:[])]);}
function save(file,b){const p=join(dir,file);writeFileSync(p,b);return p;}
function parse(c){try{return JSON.parse(c.stdout);}catch{return null;}}
function measured(fn){const t=performance.now(),before=process.memoryUsage(),value=fn();return{value,elapsed_ms:performance.now()-t,memory_before:before,memory_after:process.memoryUsage(),process_resource_usage:process.resourceUsage()};}
function codeLeb(n){const a=[];do{let b=n&127;n=Math.floor(n/128);if(n)b|=128;a.push(b);}while(n);return Buffer.from(a);}
function wasmFixture(value){return Buffer.from('0061736d010000000105016000017f03020100070a0106616e7377657200000a0601040041'+value.toString(16)+'0b','hex');}
function safeFixture(value,deep=false){let extra={notice:'benign nested provenance'};for(let i=0;i<35;i++)extra={next:extra};const h=Buffer.from(JSON.stringify({weight:{dtype:'F32',shape:[4],data_offsets:[0,16],...(deep?{documentation:extra}:{})},...(deep?{__metadata__:{'documentation.notes':'ordinary documentation '.repeat(2000)}}:{})}));const p=Buffer.alloc(8);p.writeBigUInt64LE(BigInt(h.length));const b=Buffer.alloc(16);[value,-2,0,7.5].forEach((x,i)=>b.writeFloatLE(x,i*4));return Buffer.concat([p,h,b]);}
function ggufFixture(value){const b=Buffer.alloc(80);b.write('GGUF');b.writeUInt32LE(3,4);b.writeBigUInt64LE(1n,8);b.writeBigUInt64LE(6n,24);b.write('weight',32);b.writeUInt32LE(1,38);b.writeBigUInt64LE(4n,42);[value,-2,0,7.5].forEach((v,i)=>b.writeFloatLE(v,64+i*4));return b;}
function sqliteFixture(seed){const p=join(dir,`owned-${seed}.sqlite`),db=new DatabaseSync(p);db.exec('CREATE TABLE business(id INTEGER PRIMARY KEY,name TEXT,amount REAL,payload BLOB)');db.prepare('INSERT INTO business VALUES (?,?,?,?)').run(7,'orchid',12.5,Buffer.from('00ff','hex'));db.close();return readFileSync(p);}
function benignSqlite(seed){const p=join(dir,`benign-${seed}.sqlite`),db=new DatabaseSync(p);db.exec("CREATE TABLE business(id INTEGER PRIMARY KEY,name TEXT,amount REAL,payload BLOB); INSERT INTO business VALUES (7,'orchid',12.5,x'00ff'); CREATE TABLE documentation(id INTEGER PRIMARY KEY,body TEXT); CREATE VIEW guide AS SELECT id,body FROM documentation;");const s=db.prepare('INSERT INTO documentation VALUES (?,?)');for(let i=0;i<80;i++)s.run(i,'ordinary reference documentation '.repeat(500));db.close();return readFileSync(p);}
function wasmHandoff(b){let p=8;const parts=[b.subarray(0,8)];while(p<b.length){const start=p,id=b[p++];let size=0,m=1;while(true){const x=b[p++];size+=(x&127)*m;if(!(x&128))break;m*=128;}const end=p+size;if(id!==0&&id!==7)parts.push(b.subarray(start,end));if(id===7)parts.push(Buffer.from('070a0106616e737765720000','hex'));p=end;}return Buffer.concat(parts);}
function safeHandoff(b){const length=Number(b.readBigUInt64LE()),h=JSON.parse(b.toString('utf8',8,8+length)),clean={};for(const [k,v]of Object.entries(h))if(k!=='__metadata__')clean[k]={dtype:v.dtype,shape:v.shape,data_offsets:v.data_offsets};const text=Buffer.from(JSON.stringify(clean)),p=Buffer.alloc(8);p.writeBigUInt64LE(BigInt(text.length));return Buffer.concat([p,text,b.subarray(8+length)]);}
function benignWasm(b){let p=8;const parts=[b.subarray(0,8)];while(p<b.length){const start=p,id=b[p++];let size=0,m=1;while(true){const x=b[p++];size+=(x&127)*m;if(!(x&128))break;m*=128;}const end=p+size;if(id!==0)parts.push(b.subarray(start,end));p=end;}return Buffer.concat(parts);}
const image='node@sha256:d862bb5d082c5ae0210ac07e8c0344cb8cf7bef6d78e9b8c50c179da923108ea';
function dynamicWasm(paths,expected,seed){const name='anti-bla-data-'+randomUUID().slice(0,12),runner=join(dir,`dynamic-${seed}.mjs`);
  writeFileSync(runner,`import{readFileSync}from'node:fs';const values=[];for(const path of ${JSON.stringify(paths.map(p=>'/fixture/'+p.split(/[\\/]/).at(-1)))}){const m=await WebAssembly.instantiate(readFileSync(path));values.push(m.instance.exports.answer());}const ok=values.every(x=>x===${expected});console.log(JSON.stringify({controlled_fixture:true,selected_export:'answer',values,expected:${expected},ok,scope:'selected constant export on own no-import fixture; export enumeration and custom sections differ',memory:process.memoryUsage(),resource:process.resourceUsage()}));if(!ok)process.exitCode=1;`);
  const create=command('docker',['--context','desktop-linux','create','--name',name,'--label','anti-bla.data-qualification=true','--platform','linux/amd64','--pull','never','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','64','--memory','256m','--cpus','1','--user','65534:65534','--mount',`type=bind,source=${dir},target=/fixture,readonly`,'--workdir','/fixture','--entrypoint','node',image,'/fixture/'+runner.split(/[\\/]/).at(-1)]);
  if(create.exit!==0)return{status:'UNKNOWN',create};let run,inspection,cleanup;try{run=command('docker',['--context','desktop-linux','start','--attach',name]);inspection=command('docker',['--context','desktop-linux','inspect',name]);}finally{cleanup=command('docker',['--context','desktop-linux','rm','-f',name]);}return{status:run?.exit===0?'selected-behavior-confirmed':'UNKNOWN',run,inspection,cleanup,assertion:parse(run)};
}
if(process.argv.includes('--retry-wasm')){
  const inputs=JSON.parse(readFileSync(join(root,'scratch/data-formats/wasm-retry-input.json'),'utf8')),runs=[];
  for(const x of inputs){console.log('bounded WASM REA retry',x.seed);const clean=rea(x.clean,'inspect-wasm-artifact'),protectedRun=rea(x.path,'inspect-wasm-artifact'),handoff=rea(x.handoff,'inspect-wasm-artifact');
    const cleanJson=parse(clean),protectedJson=parse(protectedRun),handoffJson=parse(handoff),b=readFileSync(x.path),anti=measured(()=>inspectWasm(b,{exportName:'answer'}));
    const record={seed:x.seed,original:{path:x.path,sha256:digest(b),byteLength:b.length},clean,protected:protectedRun,handoff,
      clean_state:cleanJson?.data?.normalized_result?.interface?.state??'UNKNOWN',protected_state:protectedJson?.data?.normalized_result?.interface?.state??'UNKNOWN',handoff_state:handoffJson?.data?.normalized_result?.interface?.state??'UNKNOWN',
      protected_issues:protectedJson?.data?.normalized_result?.interface?.issues??null,anti,
      status:'REVIEW_PENDING',ruling:'Filter selected public CLI delivery fields only. Original operation/analysis limits unchanged; partial interface stays partial. A complete parser inventory alone is not a behavior assertion.'};runs.push(record);
    writeFileSync(join(root,'reports/C6-data-wasm-rea-retry.json'),JSON.stringify({schema:'anti-bla.c6-wasm-rea-retry/1',audit_source:'implementation-worker',pinned:report.pinned,runs,commands,source_attempt:'reports/C6-data-qualification-rejected-capture.json',dynamic_supplement:'reports/C6-data-dynamic.json'},null,2));
  }
  console.log(JSON.stringify(runs.map(r=>({seed:r.seed,clean:r.clean_state,protected:r.protected_state,handoff:r.handoff_state}))));process.exit(0);
}
if(process.argv.includes('--arithmetic-wasm')){
  const pairs=[[0,0],[1,2],[-1,0],[2147483647,1],[-2147483648,-1],[2147483647,2147483647],[-2147483648,-2147483648],[65536,-65536]];
  const cases=[{seed:'c6-add-713',constant:7,expected:[7,10,6,-2147483641,-2147483642,5,7,7]},
    {seed:'c6-add-819',constant:19,expected:[19,22,18,-2147483629,-2147483630,17,19,19]},
    {seed:'c6-add-927',constant:31,expected:[31,34,30,-2147483617,-2147483618,29,31,31]}];
  const runs=[];
  for(const c of cases){console.log('arithmetic WASM qualification',c.seed);const clean=Buffer.from('0061736d0100000001070160027f7f017f03020100070a0106616e7377657200000a0c010a00200020016a41'+c.constant.toString(16).padStart(2,'0')+'6a0b','hex');
    const protectedBytes=protectWasmBinary(clean,{intensity:'bankrupt',seed:c.seed}).buffer,handoffBytes=wasmHandoff(protectedBytes),cleanPath=save(c.seed+'-clean.wasm',clean),protectedPath=save(c.seed+'-protected.wasm',protectedBytes),handoffPath=save(c.seed+'-handoff.wasm',handoffBytes);
    const anti=measured(()=>inspectWasm(protectedBytes,{exportName:'answer'})),cleanRun=rea(cleanPath,'inspect-wasm-artifact'),protectedRun=rea(protectedPath,'inspect-wasm-artifact'),handoffRun=rea(handoffPath,'inspect-wasm-artifact');
    const body=Buffer.from([0,32,0,32,1,106,65,c.constant,106,11]).toString('base64');
    const record={seed:c.seed,emitter:'actual pinned protectWasmBinary bankrupt',expected_constant:c.constant,pairs,expected:c.expected,clean:{path:cleanPath,sha256:digest(clean)},protected:{path:protectedPath,sha256:digest(protectedBytes)},handoff:{path:handoffPath,sha256:digest(handoffBytes)},anti,
      static_assertion:anti.value.status==='ok'&&anti.value.selected.body.base64===body&&JSON.stringify(anti.value.selected.type)==='{"params":["i32","i32"],"results":["i32"]}'&&anti.value.selected.aliasCount===251,
      rea_clean:cleanRun,rea_protected:protectedRun,rea_handoff:handoffRun,clean_state:parse(cleanRun)?.data?.normalized_result?.interface?.state??'UNKNOWN',protected_state:parse(protectedRun)?.data?.normalized_result?.interface?.state??'UNKNOWN',handoff_state:parse(handoffRun)?.data?.normalized_result?.interface?.state??'UNKNOWN',status:'STATIC_REVIEW_PENDING; dynamic supplement required',global_equivalence:'UNKNOWN'};
    writeFileSync(join(dir,`dynamic-${c.seed}.mjs`),`import{readFileSync}from'node:fs';const pairs=${JSON.stringify(pairs)},expected=${JSON.stringify(c.expected)},outputs=[];for(const path of ${JSON.stringify([cleanPath,protectedPath,handoffPath].map(p=>'/fixture/'+p.split(/[\\/]/).at(-1)))}){const m=await WebAssembly.instantiate(readFileSync(path));outputs.push(pairs.map(([a,b])=>m.instance.exports.answer(a,b)));}const ok=outputs.every(a=>JSON.stringify(a)===JSON.stringify(expected));console.log(JSON.stringify({controlled_fixture:true,task:'two i32 additions with wraparound',pairs,expected,outputs,ok,scope:'Own no-import literal arithmetic fixture and tested input pairs only; whole-module/global equivalence UNKNOWN',memory:process.memoryUsage(),resource:process.resourceUsage()}));if(!ok)process.exitCode=1;`);
    runs.push(record);writeFileSync(join(root,'reports/C6-data-wasm-arithmetic.json'),JSON.stringify({schema:'anti-bla.c6-wasm-arithmetic/1',pinned:report.pinned,audit_source:'implementation-worker',records:runs,commands,status:'REVIEW_PENDING',dynamic_supplement:'reports/C6-data-wasm-arithmetic-dynamic.json'},null,2));
  }console.log(JSON.stringify(runs.map(r=>({seed:r.seed,static:r.static_assertion,clean:r.clean_state,protected:r.protected_state,handoff:r.handoff_state}))));process.exit(0);
}
if(process.argv.includes('--gguf-candidates')){
  const initial=JSON.parse(readFileSync(join(root,'reports/C6-data-qualification.json'),'utf8')),runs=[];
  const literals={'c6-independent-713':[1.25,-2,0,7.5],'c6-independent-819':[2.25,-2,0,7.5],'c6-independent-927':[3.25,-2,0,7.5]};
  for(const r of initial.records.filter(r=>r.family==='gguf')){console.log('GGUF structural candidate qualification',r.seed);const b=readFileSync(r.protected.path),anti=measured(()=>inspectModel(b,{tensor:'weight'})),candidate=anti.value.recoveryCandidate;
    const rec={seed:r.seed,clean_source_rea_exit:r.rea_clean.exit,clean_source_rea_evidence:r.rea_clean_json,original:r.protected,anti,expected_literals:literals[r.seed],candidate_value_assertion:JSON.stringify(candidate?.selected?.values)===JSON.stringify(literals[r.seed]),standard_format_valid:false,global_equivalence:'UNKNOWN',status:'UNKNOWN_CONDITIONAL_CANDIDATE'};
    const ownClean=readFileSync(r.clean.path),key=Buffer.from('documentation.nesting'),kvPrefix=Buffer.alloc(8+key.length+4);kvPrefix.writeBigUInt64LE(BigInt(key.length));key.copy(kvPrefix,8);kvPrefix.writeUInt32LE(9,8+key.length);const frames=[];for(let i=0;i<35;i++){const f=Buffer.alloc(12);f.writeUInt32LE(i===34?4:9);f.writeBigUInt64LE(1n,4);frames.push(f);}const leaf=Buffer.from('7b000000','hex'),ownHeader=Buffer.from(ownClean.subarray(0,24));ownHeader.writeBigUInt64LE(1n,16);const ownPrefix=Buffer.concat([ownHeader,kvPrefix,...frames,leaf,ownClean.subarray(24,62)]),benign=Buffer.concat([ownPrefix,Buffer.alloc((32-ownPrefix.length%32)%32),ownClean.subarray(64)]),benignPath=save(r.seed+'-gguf-benign-complex.gguf',benign);
    rec.benign_complex={path:benignPath,sha256:digest(benign),origin:'Independent valid35-frame documentation array, rebuilt standard alignment, own literal tensor bytes',anti:measured(()=>inspectModel(benign,{tensor:'weight'})),rea:rea(benignPath,'inspect-model-artifact',['--hash','full'])};
    rec.benign_value_assertion=JSON.stringify(rec.benign_complex.anti.value.selected?.values)===JSON.stringify(literals[r.seed]);
    if(candidate?.selected){const s=candidate.selected,header=Buffer.alloc(24);header.write('GGUF');header.writeUInt32LE(3,4);header.writeBigUInt64LE(1n,8);const descriptor=b.subarray(s.descriptor.offset,s.descriptor.offset+s.descriptor.length),prefix=Buffer.concat([header,descriptor]),padding=Buffer.alloc((32-prefix.length%32)%32),repaired=Buffer.concat([prefix,padding,b.subarray(s.data.offset,s.data.offset+s.data.totalLength)]),p=save(r.seed+'-gguf-conditional-handoff.gguf',repaired);
      rec.handoff={path:p,sha256:digest(repaired),observable_changes:['All metadata removed','Payload repacked to standard alignment under explicit tail-fit assumptions'],anti:measured(()=>inspectModel(repaired,{tensor:'weight'})),rea:rea(p,'inspect-model-artifact',['--hash','full'])};
      rec.derivative_value_assertion=JSON.stringify(rec.handoff.anti.value.selected?.values)===JSON.stringify(literals[r.seed]);
    }runs.push(rec);writeFileSync(join(root,'reports/C6-data-gguf-candidates.json'),JSON.stringify({schema:'anti-bla.c6-gguf-candidates/1',pinned:report.pinned,audit_source:'implementation-worker',status:'UNKNOWN_CONDITIONAL_CANDIDATES_REVIEW_PENDING',records:runs,commands},null,2));
  }console.log(JSON.stringify(runs.map(r=>({seed:r.seed,clean_rea:r.clean_source_rea_exit,original_status:r.anti.value.status,candidate:r.candidate_value_assertion,handoff_rea:r.handoff?.rea.exit,derivative:r.derivative_value_assertion}))));process.exit(0);
}
for(let i=0;i<seeds.length;i++){
  const seed=seeds[i],value=i+1.25;
  const families=[
    {kind:'wasm',ext:'wasm',clean:wasmFixture(42+i),protect:b=>protectWasmBinary(b,{intensity:'bankrupt',seed}),inspect:b=>inspectWasm(b,{exportName:'answer'}),cmd:'inspect-wasm-artifact',extra:[],check:r=>r.status==='ok'&&r.selected.body.base64===Buffer.from([0,65,42+i,11]).toString('base64')&&r.selected.type.results[0]==='i32'&&r.selected.aliasCount===251},
    {kind:'sqlite',ext:'sqlite',clean:sqliteFixture(seed),protect:b=>protectSqliteBuffer(b,{intensity:'bankrupt',seed}),inspect:b=>inspectSqlite(b,{table:'business'}),cmd:'inspect-sqlite-database',extra:['--table','business','--column','id','--column','name','--column','amount','--column','payload'],check:r=>r.status==='ok'&&r.rows[0]?.rowid===7&&r.rows[0]?.values[1]?.value==='orchid'&&r.rows[0]?.values[2]?.value===12.5&&r.rows[0]?.values[3]?.base64==='AP8='},
    {kind:'safetensors',ext:'safetensors',clean:safeFixture(value),protect:b=>protectSafetensorsBuffer(b,{intensity:'bankrupt',seed}),inspect:b=>inspectModel(b,{tensor:'weight'}),cmd:'inspect-model-artifact',extra:['--hash','full'],check:r=>r.status==='ok'&&JSON.stringify(r.selected.values)===JSON.stringify([value,-2,0,7.5])},
    {kind:'gguf',ext:'gguf',clean:ggufFixture(value),protect:b=>protectGgufBuffer(b,{intensity:'bankrupt',seed}),inspect:b=>inspectModel(b,{tensor:'weight'}),cmd:'inspect-model-artifact',extra:['--hash','full'],check:r=>r.status==='ok'&&JSON.stringify(r.selected.values)===JSON.stringify([value,-2,0,7.5])},
  ];
  for(const f of families){console.log('qualifying',seed,f.kind);const cleanPath=save(`${seed}-clean.${f.ext}`,f.clean),emitter=measured(()=>f.protect(f.clean)),protectedBytes=emitter.value.buffer,protectedPath=save(`${seed}-protected.${f.ext}`,protectedBytes);
    const cleanAnti=measured(()=>f.inspect(f.clean)),anti=measured(()=>f.inspect(protectedBytes)),baseline=rea(cleanPath,f.cmd,f.extra),protectedBaseline=rea(protectedPath,f.cmd,f.extra);
    const normalCheck=f.kind==='wasm'?cleanAnti.value.status==='ok'&&cleanAnti.value.selected.aliasCount===1:f.check(cleanAnti.value);
    const rec={family:f.kind,seed,origin:'independent literal/owned Node SQLite fixture; actual pinned BLA public emitter',emitter_api:{wasm:'protectWasmBinary',sqlite:'protectSqliteBuffer',safetensors:'protectSafetensorsBuffer',gguf:'protectGgufBuffer'}[f.kind],emitter_options:{intensity:'bankrupt',seed},clean:{path:cleanPath,sha256:digest(f.clean),byteLength:f.clean.length},protected:{path:protectedPath,sha256:digest(protectedBytes),byteLength:protectedBytes.length},emitter:{...emitter,value:{...emitter.value,buffer:undefined}},clean_anti:cleanAnti,protected_anti:anti,normal_control_assertion:normalCheck,actual_recovery_assertion:f.check(anti.value),rea_clean:baseline,rea_protected:protectedBaseline,rea_clean_json:parse(baseline),rea_protected_json:parse(protectedBaseline),global_equivalence:'UNKNOWN',status:'UNKNOWN'};
    const benign=f.kind==='wasm'?benignWasm(protectedBytes):f.kind==='sqlite'?benignSqlite(seed):f.kind==='safetensors'?safeFixture(value,true):null;
    if(benign){const p=save(`${seed}-benign.${f.ext}`,benign);rec.benign={path:p,sha256:digest(benign),byteLength:benign.length,anti:measured(()=>f.inspect(benign)),rea:rea(p,f.cmd,f.extra),note:f.kind==='wasm'?'Same real long-name aliases without custom bait; equally complex interface.':f.kind==='sqlite'?'Ordinary documentation pages and view; no generated UDFs.':'Benign deeply nested documentation and long metadata; same parser complexity family.'};}
    if(f.kind==='wasm'||f.kind==='safetensors'){const derived=f.kind==='wasm'?wasmHandoff(protectedBytes):safeHandoff(protectedBytes),p=save(`${seed}-selected-handoff.${f.ext}`,derived),handoff=rea(p,f.cmd,f.extra);
      rec.handoff={path:p,sha256:digest(derived),byteLength:derived.length,rea:handoff,anti:measured(()=>f.inspect(derived)),observable_changes:f.kind==='wasm'?['Removed custom sections','Removed all exports except answer; export enumeration differs']:['Removed metadata and extra descriptor keys; tensor descriptors/bytes retained'],equivalence:'UNKNOWN outside selected task'};
      if(f.kind==='wasm')rec.dynamic=dynamicWasm([cleanPath,protectedPath,p],42+i,seed);
    }
    rec.original_immutable=digest(readFileSync(cleanPath))===rec.clean.sha256&&digest(readFileSync(protectedPath))===rec.protected.sha256;
    rec.status=rec.actual_recovery_assertion&&rec.normal_control_assertion&&rec.original_immutable?'SELECTED_STATIC_RECOVERY':'UNKNOWN';
    records.push(rec);writeFileSync(join(root,'reports/C6-data-qualification.json'),JSON.stringify(report,null,2));
  }
}
report.finished=new Date().toISOString();report.status=records.every(r=>r.status==='SELECTED_STATIC_RECOVERY')?'SELECTED_STATIC_RECOVERY_REVIEW_PENDING':'PARTIAL_UNKNOWN_REVIEW_PENDING';
report.summary=Object.fromEntries(['wasm','sqlite','safetensors','gguf'].map(f=>[f,{runs:records.filter(r=>r.family===f).length,selected_recovery:records.filter(r=>r.family===f&&r.actual_recovery_assertion).length,unknown:records.filter(r=>r.family===f&&!r.actual_recovery_assertion).length}]));
writeFileSync(join(root,'scratch/data-formats/wasm-retry-input.json'),JSON.stringify(records.filter(r=>r.family==='wasm').map(r=>({seed:r.seed,path:r.protected.path,clean:r.clean.path,handoff:r.handoff.path})),null,2));
writeFileSync(join(root,'reports/C6-data-qualification.json'),JSON.stringify(report,null,2));console.log(JSON.stringify({status:report.status,summary:report.summary,report:'reports/C6-data-qualification.json'}));

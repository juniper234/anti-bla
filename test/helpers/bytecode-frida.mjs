// Fixed owned-fixture Frida qualification. Native Frida is never imported on host.
import {readFileSync,writeFileSync,mkdirSync,existsSync,openSync,closeSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {createHash} from 'node:crypto';
import {spawn} from 'node:child_process';
import {performance} from 'node:perf_hooks';
import {homedir} from 'node:os';
const researchPython=process.env.ANTI_BLA_RESEARCH_PYTHON??join(process.env.LOCALAPPDATA??join(homedir(),'AppData','Local'),'Programs','Python','Python313','python.exe');
const root=resolve(import.meta.dirname,'../..'),stamp=new Date().toISOString().replace(/[:.]/g,'-'),work=join(root,'scratch/bytecode','frida-'+stamp),tool=join(root,'.tools/bytecode/frida-17.4.2-linux');mkdirSync(work,{recursive:true});mkdirSync(tool,{recursive:true});
const hash=b=>createHash('sha256').update(b).digest('hex'),identity=p=>{const b=readFileSync(p);return{path:p,bytes:b.length,sha256:hash(b)};},reportPath=join(root,'reports',`C6-bytecode-frida-${stamp}.json`);
const selected=join(root,'reports/C6-bytecode-2026-10-30T04-20-33-440Z.json'),prior=JSON.parse(readFileSync(selected,'utf8')),fixtures=resolve(prior.commands[0].stdout.path,'..'),image=prior.environment.container_image;
const report={schema:'anti-bla.real-frida-owned-fixtures/1',started_utc:new Date().toISOString(),audit_source:'implementation-worker',status:'RUNNING',source_cdp_report:identity(selected),image,scope:'Actual Frida child spawn/attach and observed owned process output; not REA collector saturation or arbitrary host target execution.',harness:identity(import.meta.filename),commands:[],records:[],peak_rss:null,cpu_seconds:null,token_count:null,cost_usd:null};
const checkpoint=()=>writeFileSync(reportPath,JSON.stringify(report,null,2));let index=0;
async function command(label,executable,args,timeout=45000){const id=String(++index).padStart(3,'0'),out=join(work,id+'-'+label+'.stdout'),err=join(work,id+'-'+label+'.stderr'),a=openSync(out,'wx'),b=openSync(err,'wx'),started=new Date().toISOString(),t=performance.now();let child,expired=false;const result=await new Promise(done=>{child=spawn(executable,args,{cwd:root,windowsHide:true,stdio:['ignore',a,b]});const timer=setTimeout(()=>{expired=true;child.kill();},timeout);child.on('error',e=>{clearTimeout(timer);done({exit_code:null,error:e.message});});child.on('exit',(code,signal)=>{clearTimeout(timer);done({exit_code:code,signal});});});closeSync(a);closeSync(b);const r={id,label,started_utc:started,executable,args,...result,timed_out:expired,wall_ms:performance.now()-t,stdout:identity(out),stderr:identity(err),peak_rss:null,cpu_seconds:null};report.commands.push(r);checkpoint();return r;}
const output=r=>readFileSync(r.stdout.path,'utf8'),json=r=>{try{return JSON.parse(output(r));}catch{return null;}};
// Official PyPI index digest is checked before extracting the pinned wheel.
const metadataUrl='https://pypi.org/pypi/frida/17.4.2/json',metadataResponse=await fetch(metadataUrl);if(!metadataResponse.ok)throw new Error('Frida PyPI index '+metadataResponse.status);const metadataBytes=Buffer.from(await metadataResponse.arrayBuffer()),metadata=JSON.parse(metadataBytes),asset=metadata.urls.find(x=>x.filename==='frida-17.4.2-cp37-abi3-manylinux_2_5_x86_64.whl');if(!asset||asset.size>64*1024*1024)throw new Error('Pinned wheel missing/too large');
const metadataPath=join(work,'pypi-frida-17.4.2.json');writeFileSync(metadataPath,metadataBytes);const wheel=join(root,'.tools/bytecode',asset.filename);if(!existsSync(wheel)){const response=await fetch(asset.url);if(!response.ok)throw new Error('wheel HTTP '+response.status);const bytes=Buffer.from(await response.arrayBuffer());if(bytes.length!==asset.size||hash(bytes)!==asset.digests.sha256)throw new Error('wheel checksum mismatch');writeFileSync(wheel,bytes);}if(hash(readFileSync(wheel))!==asset.digests.sha256)throw new Error('cached wheel checksum mismatch');
report.acquisition={metadata_url:metadataUrl,metadata:identity(metadataPath),url:asset.url,expected_sha256:asset.digests.sha256,wheel:identity(wheel),verified:true,license:metadata.info.license,imported_on_host:false};checkpoint();
const installer=join(work,'trusted-extract-wheel.py');writeFileSync(installer,String.raw`import sys,zipfile,json
from pathlib import Path
root=Path(sys.argv[2]).resolve()
with zipfile.ZipFile(sys.argv[1]) as z:
 for entry in z.infolist():
  p=(root/entry.filename).resolve()
  if not p.is_relative_to(root):raise ValueError('wheel path outside own tools directory')
 z.extractall(root)
print(json.dumps({'trusted_checksum_verified_wheel_extracted':True}))
`);
const extraction=await command('verified-wheel-extract',researchPython,['-I',installer,wheel,tool]);if(extraction.exit_code!==0)throw new Error('wheel extraction failed');
const probe=join(work,'trusted-frida-probe.py');writeFileSync(probe,String.raw`import sys,json,time,threading,traceback
sys.path.insert(0,'/tools')
import frida
target=sys.argv[1]
if not target.startswith('/probe/') or not target.endswith('.mjs') or '..' in target:raise ValueError('fixed owned launcher only')
messages=[];chunks=[];ready=threading.Event();device=frida.get_local_device();pid=None;session=None
def out(pid_out,fd,data):
 if pid_out==pid and fd==1 and sum(len(x) for x in chunks)+len(data)<=65536:
  chunks.append(data)
  if b'owned_calls' in b''.join(chunks):ready.set()
device.on('output',out)
try:
 pid=device.spawn(['/usr/local/bin/node',target],stdio='pipe')
 session=device.attach(pid)
 script=session.create_script('''send({event:"real-agent-loaded",pid:Process.id,arch:Process.arch});
 const p=Module.findGlobalExportByName("write");
 if(p)Interceptor.attach(p,{onEnter(args){const n=args[2].toInt32();if(args[0].toInt32()===1&&n>0&&n<=4096){try{send({event:"actual-libc-write",text:args[1].readUtf8String(n)});}catch(e){send({event:"bounded-read-error",message:String(e)});}}}});
 ''')
 script.on('message',lambda message,data:messages.append(message));script.load();device.resume(pid);completed=ready.wait(10);time.sleep(0.1)
 print(json.dumps({'status':'observed' if completed else 'output-timeout','frida_version':frida.__version__,'target':target,'pid':pid,'agent_messages':messages,'stdout_hex':b''.join(chunks).hex(),'stdout_text':b''.join(chunks).decode('utf8','replace'),'real_child_attach':True,'target_executed':True}))
 if not completed:sys.exit(2)
except Exception as e:
 print(json.dumps({'status':'refused','error_type':type(e).__name__,'message':str(e),'real_child_attach':False,'target_executed':pid is not None}));sys.exit(3)
finally:
 if session:
  try:session.detach()
  except Exception:pass
 if pid:
  try:device.kill(pid)
  except Exception:pass
`);
for(const [i,addend]of [[1,11],[2,13],[3,17]]){
 const seed=`bytecode-independent-${i}-20261030`,endpoint='/api/owned/'+seed,variants=[];
 for(const kind of ['clean','protected','handoff']){
  const original=join(fixtures,seed,'runtime-'+kind,'index.mjs'),originalIdentity=identity(original),launcher=join(work,seed+'-'+kind+'.mjs');
  writeFileSync(launcher,`import {register} from ${JSON.stringify('file:///fixtures/'+seed+'/runtime-'+kind+'/index.mjs')};\nconst calls=[];register({post:(...args)=>calls.push(args)});console.log(JSON.stringify({owned_calls:calls}));setInterval(()=>{},1000);\n`);
  const name=`anti-bla-bytecode-frida-${stamp.toLowerCase()}-${i}-${kind}`,args=['run','--rm','--name',name,'--network','none','--read-only','--user','65534:65534','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','128','--memory','1536m','--cpus','2','--tmpfs','/tmp:rw,nosuid,nodev,size=768m','--mount',`type=bind,src=${fixtures},dst=/fixtures,readonly`,'--mount',`type=bind,src=${work},dst=/probe,readonly`,'--mount',`type=bind,src=${tool},dst=/tools,readonly`,'--env','HOME=/tmp',image,'python3','-I','/probe/trusted-frida-probe.py','/probe/'+seed+'-'+kind+'.mjs'];
  const r=await command('frida-'+seed+'-'+kind,'docker',args);if(r.timed_out)await command('owned-timeout-cleanup','docker',['rm','--force',name]);const v=json(r);let observed=null;try{observed=JSON.parse(v.stdout_text.trim()).owned_calls;}catch{}
  variants.push({kind,input:originalIdentity,launcher:identity(launcher),command:r.id,exit_code:r.exit_code,observation:v,assertions:{actual_attach:v?.real_child_attach===true,selected_task:JSON.stringify(observed)===JSON.stringify([[endpoint,addend]]),actual_agent_loaded:v?.agent_messages?.some(m=>m.payload?.event==='real-agent-loaded')??false,actual_write_intercept:v?.agent_messages?.some(m=>m.payload?.event==='actual-libc-write')??false,original_unchanged:identity(original).sha256===originalIdentity.sha256}});checkpoint();
 }
 report.records.push({seed,expected:{endpoint,amount:addend},variants,ruling:variants.every(v=>v.assertions.actual_attach&&v.assertions.selected_task)?'ACTUAL_FRIDA_CHILD_ATTACH_AND_SELECTED_OUTPUT_RECOVERY; REA collector saturation remains unmeasured':'UNKNOWN Frida profile refused/failed; exact raw cause retained, no security change made'});checkpoint();console.log(JSON.stringify({seed,assertions:variants.map(v=>({kind:v.kind,...v.assertions}))}));
}
const cleanup=await command('owned-containers-check','docker',['ps','-a','--filter','name=anti-bla-bytecode-frida-','--format','{{.Names}}']);report.cleanup={exit_code:cleanup.exit_code,remaining:output(cleanup).trim()};report.finished_utc=new Date().toISOString();report.status='MEASURED_REVIEW_PENDING';checkpoint();console.log(JSON.stringify({report:reportPath,records:report.records.length,cleanup:report.cleanup}));

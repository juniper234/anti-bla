// Re-derive selected historical tasks from retained raw outputs, not stored flags.
// This executes no targets, emitters or providers and never rewrites historical reports.
import {readFileSync} from 'node:fs';
import {expectedBytecodeSeed,retainedRecordTaskCases,bytecodeSha} from './bytecode-records.mjs';
import {evaluateBoundTask} from './bytecode-predicates.mjs';
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
export function retainedOutput(report,reference){
 const id=typeof reference==='string'?reference:reference?.command_id;
 const matches=report.commands.filter(c=>c.id===id);if(matches.length!==1)throw new Error('Missing/ambiguous command '+id);
 const command=matches[0],bytes=readFileSync(command.stdout.path);
 const hashOk=bytecodeSha(bytes)===command.stdout.sha256&&bytes.length===command.stdout.bytes;
 const referenceOk=typeof reference==='string'||reference.stdout?.sha256===command.stdout.sha256&&reference.stdout?.path===command.stdout.path&&reference.exit_code===command.exit_code&&reference.timed_out===command.timed_out;
 let raw=null;try{raw=JSON.parse(bytes);}catch{}
 return{command,bytes,text:bytes.toString('utf8'),raw,verified:hashOk&&referenceOk,success:hashOk&&referenceOk&&command.exit_code===0&&command.timed_out===false&&!command.signal&&!command.error};
}
export function rederiveRecordTasks(report,entry){
 const expected=expectedBytecodeSeed(entry.seed),tasks=[];
 const add=(label,ok,output,details=null,expectedRecovery=true)=>tasks.push({label,ok:ok===true,expected_recovery:expectedRecovery,verified_command:output?.verified??null,command_id:output?.command?.id??null,exit_code:output?.command?.exit_code??null,stdout:output?.command?.stdout??null,details});
 for(const c of retainedRecordTaskCases(report,entry)){
  const result=evaluateBoundTask(c.kind,c.expected,c.context);
  add(c.kind+':'+c.variant,result.ok,{verified:result.binding,command:c.context.command},{binding:result.binding,reason:result.reason,artifact:c.context.artifact,selected_path:c.context.selectedPath,operation:c.raw?.operation,provider:c.raw?.provider?.id,typed_result:c.kind==='evm'?c.raw.normalized_result?.functions:c.kind==='pcap'?c.raw.normalized_result?.packets:c.kind==='android-package'?{package_name:c.raw.normalized_result?.package_name,manifest_status:c.raw.normalized_result?.manifest?.status}:{native_inventory:c.raw.normalized_result?.native_inventory,selected_declaration_ids:c.raw.normalized_result?.selected_declaration_ids,declarations:c.raw.normalized_result?.declarations,bindings:c.raw.normalized_result?.bindings,candidates:c.raw.normalized_result?.candidates}});
 }
 if(entry.family==='beam')for(const key of ['official_clean','official_protected','normal_control']){
  const out=retainedOutput(report,entry[key]),s=out.text;
  add(key,out.success&&s.includes('{function,score,1,')&&s.includes('{score,1}')&&new RegExp("gc_bif,'\\*',[\\s\\S]*?integer,"+expected.multiplier+'}').test(s)&&new RegExp("gc_bif,'\\+',[\\s\\S]*?integer,"+expected.amount+'}').test(s),out,{body:s});
 }
 if(entry.family==='ptx'){
  for(const key of ['clean','protected','normal_control']){const out=retainedOutput(report,entry[key]),n=out.raw?.normalized_result,ks=n?.kernels?.filter(k=>k.name==='owned_score_'+expected.n);add(key,out.success&&ks?.length===1&&ks[0].parameter_count===1&&ks[0].parameters?.length===1&&ks[0].parameters[0].type==='.u64',out,{selected_kernels:ks});}
  add('selected-instruction-bytes',readFileSync(entry.emission.input.path).equals(readFileSync(entry.anti_handoff.derived.path)),null,entry.anti_handoff.derived);
 }
 const methodTask=(reference,label,obfuscated=false)=>{const out=retainedOutput(report,reference),n=out.raw?.normalized_result,body=n?.source?.text;add(label,out.success&&out.raw?.operation==='inspect_android_method'&&out.raw.provider?.id==='jadx'&&n?.class_name===(obfuscated?'a.a.a':'defpackage.OwnedFixture')&&n.method?.name===(obfuscated?'a':'score')&&n.method.dex_descriptor==='(I)I'&&n.body_status==='available'&&n.source?.status==='complete'&&new RegExp('return \\(i \\* '+expected.multiplier+'\\) \\+ '+expected.amount+';').test(body??''),out,{class_name:n?.class_name,method:n?.method,body_status:n?.body_status,source:n?.source,mapping_status:n?.mapping?.coverage});};
 if(['android-dex','android-r8-manifest-jni','android-genuine-obfuscated-r8'].includes(entry.family)){
  const ob=entry.family==='android-genuine-obfuscated-r8';for(const key of ['clean','protected',...(ob?['explicit_conflicting_decoy_mapping']:['normal_control'])])methodTask(entry[key],key,ob);
  if(ob)methodTask(entry.anti_handoff.trusted_external_mapping,'trusted-external-mapping',true);
 }
 if(entry.family==='android-authoritative-sidecars')methodTask(entry.protected.method,'selected-method');
 if(entry.family==='il2cpp-parser-only')for(const key of ['clean','protected','normal_control']){const out=retainedOutput(report,entry[key]),rows=out.raw?.normalized_result?.string_literals;add(key,out.success&&out.raw?.operation==='inspect_il2cpp_metadata'&&Array.isArray(rows)&&rows.length===1&&rows[0].value==='owned-literal-'+entry.seed,out,{scope:'synthetic parser control only',string_literals:rows});}
 if(entry.family==='runtime-cross-cutting')for(const key of ['clean','protected','anti']){
  const out=retainedOutput(report,entry.actual_cdp[key]),raw=out.raw,selected='/fixtures/'+entry.seed+'/runtime-'+(key==='anti'?'handoff':key)+'/index.mjs',calls=raw?.evaluated?.result?.value?.calls;
  const observed=out.success&&raw?.target===selected&&!raw.evaluated?.exceptionDetails&&Array.isArray(raw.coverage)&&raw.coverage.some(s=>s.url==='file://'+selected)&&same(calls,[[expected.endpoint,expected.amount]]);
  const rejected=out.verified&&out.command.exit_code!==0&&!!raw?.evaluated?.exceptionDetails&&raw?.evaluated?.result?.value?.code==='ERR_VM_DYNAMIC_IMPORT_CALLBACK_MISSING';
  // A rejected task remains failed recovery even when its known failure is verified.
  add(key,observed,out,{selected_path:selected,calls,known_rejected_import_attempt:rejected,exception:raw?.evaluated?.exceptionDetails??null},!rejected);
 }
 if(entry.variants)for(const v of entry.variants){
  const out=retainedOutput(report,v.command),raw=out.raw,events=raw?.agent_messages?.filter(m=>m.type==='send').map(m=>m.payload)??[];
  let calls;try{calls=JSON.parse(raw.stdout_text.trim()).owned_calls;}catch{}
  const writes=events.filter(m=>m.event==='actual-libc-write').map(m=>m.text).join('');
  add(v.kind,out.success&&raw?.real_child_attach===true&&raw.frida_version==='17.4.2'&&events.some(e=>e.event==='real-agent-loaded'&&e.pid===raw.pid)&&same(calls,[[expected.endpoint,expected.amount]])&&writes===JSON.stringify({owned_calls:[[expected.endpoint,expected.amount]]})+'\n',out,{calls,frida_version:raw?.frida_version,agent_pid:raw?.pid,agent_events:events.map(e=>e.event),intercepted_text:writes});
 }
 return tasks;
}

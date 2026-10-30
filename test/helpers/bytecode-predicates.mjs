// Research qualification predicates: exact own selected tasks, never carrier text.
import {createHash} from 'node:crypto';
const singleton=(values,value)=>Array.isArray(values)&&values.length===1&&values[0]===value;
const empty=values=>Array.isArray(values)&&values.length===0;
const uint=n=>Number.isSafeInteger(n)&&n>=0;
export function hasEvmTask(raw,expected){
 const rows=raw?.normalized_result?.functions;
 if(!/^0x[0-9a-f]{8}$/.test(expected?.selector??'')||!uint(expected?.bytecodeOffset)||!Array.isArray(rows)||rows.length===0)return false;
 const selected=rows.filter(f=>f?.selector===expected.selector);
 return selected.length===1&&selected[0].bytecode_offset===expected.bytecodeOffset;
}
export function hasPacketTask(raw,expected){
 const n=raw?.normalized_result,w=n?.output_window,s=n?.selection;
 if(!n||!Array.isArray(n.packets)||n.packets.length!==1||n.read_scope!=='to-eof'||w?.returned_packets!==1||w.matching_packets!==1||w.has_more!==false)return false;
 if(!Array.isArray(s?.fields)||s.fields.length!==4||!['ip.src','ip.dst','udp.srcport','data.data'].every(f=>s.fields.includes(f))||s.display_filter!=='udp.srcport == 42123'||s.packet_limit!==null||s.match_offset!==0||s.match_limit!==1)return false;
 const p=n.packets[0];return typeof expected?.payloadHex==='string'&&/^(?:[0-9a-f]{2})+$/.test(expected.payloadHex)&&singleton(p?.['frame.number'],expected.frameNumber)&&singleton(p?.['ip.src'],expected.sourceIp)&&singleton(p?.['ip.dst'],expected.destinationIp)&&singleton(p?.['udp.srcport'],expected.sourcePort)&&singleton(p?.['data.data'],expected.payloadHex);
}
export function hasAndroidPackageTask(raw,expected){
 const n=raw?.normalized_result;return typeof expected?.packageName==='string'&&expected.packageName.length>0&&n?.package_name===expected.packageName&&n.manifest?.status==='complete';
}
export function hasJniTask(raw,expected){
 const n=raw?.normalized_result,c=n?.native_inventory?.coverage,l=n?.library_inventory;
 if(!expected||!['className','methodName','descriptor','dexEntry','abi'].every(k=>typeof expected[k]==='string'&&expected[k].length>0))return false;
 if(n?.native_inventory?.scope!=='apk-root-dex-declarations'||c?.status!=='complete'||!uint(c.dex_entries)||c.dex_entries<1||c.examined_dex_entries!==c.dex_entries||!uint(c.examined_classes)||c.examined_classes<1||!uint(c.examined_methods)||c.examined_methods<1||!empty(n.native_inventory.unknowns)||l?.status!=='complete')return false;
 if(!Array.isArray(n.declarations)||n.declarations.length!==1||!Array.isArray(n.bindings)||n.bindings.length!==1||!empty(n.candidates)||!Array.isArray(n.libraries)||n.libraries.length<1||l.selected_libraries!==n.libraries.length)return false;
 const d=n.declarations[0],b=n.bindings[0];
 if(typeof d?.declaration_id!=='string'||!d.declaration_id||d.class_name!==expected?.className||d.method_name!==expected.methodName||d.descriptor!==expected.descriptor||d.dex_entry!==expected.dexEntry||!singleton(n.selected_declaration_ids,d.declaration_id))return false;
 if(b?.declaration_id!==d.declaration_id||b.abi!==expected.abi||b.status!=='unmatched'||b.coverage!=='complete'||!empty(b.candidate_ids)||!empty(b.unknowns))return false;
 return n.libraries.some(lib=>lib?.abi===expected.abi)&&n.libraries.every(lib=>lib?.failure===null&&['status','exports_status','tables_status','relocations_status'].every(k=>lib.coverage?.[k]==='complete'));
}
const policies={evm:{operation:'inspect_evm_interface',cli:'inspect-evm-interface',provider:'evmole-interface',predicate:hasEvmTask},pcap:{operation:'inspect_packet_capture',cli:'inspect-packet-capture',provider:'tshark-capture',predicate:hasPacketTask},'android-package':{operation:'inspect_android_package',cli:'inspect-android-package',provider:'jadx',predicate:hasAndroidPackageTask},'android-jni':{operation:'inspect_android_jni_bindings',cli:'inspect-android-jni-bindings',provider:'jadx',predicate:hasJniTask}};
export function evaluateBoundTask(kind,expected,context){
 const policy=policies[kind],fail=reason=>({ok:false,binding:false,task:false,reason});
 if(!policy||!context)return fail('missing-policy-context');
 const {command,reference,stdoutBytes,artifact,selectedPath}=context;
 if(command?.exit_code!==0||command.timed_out!==false||command.error||command.signal)return fail('command-not-successful');
 if(!Buffer.isBuffer(stdoutBytes)||!command.stdout||command.stdout.bytes!==stdoutBytes.length||command.stdout.sha256!==createHash('sha256').update(stdoutBytes).digest('hex'))return fail('stdout-identity');
 if(reference&&(reference.command_id!==command.id||reference.exit_code!==command.exit_code||reference.timed_out!==command.timed_out||reference.stdout?.path!==command.stdout.path||reference.stdout?.sha256!==command.stdout.sha256||reference.stdout?.bytes!==command.stdout.bytes))return fail('command-reference');
 if(typeof selectedPath!=='string'||!selectedPath||!Array.isArray(command.args)||command.args.filter(a=>a===policy.cli).length!==1||command.args[command.args.indexOf(policy.cli)+1]!==selectedPath)return fail('command-selection');
 if(command.executable==='docker'){
  const a=command.args,at=f=>a[a.indexOf(f)+1];
  if(a[0]!=='run'||!a.includes('--rm')||at('--network')!=='none'||!a.includes('--read-only')||at('--user')!=='65534:65534'||at('--cap-drop')!=='ALL'||at('--security-opt')!=='no-new-privileges'||at('--pids-limit')!=='128'||at('--memory')!=='1536m'||at('--cpus')!=='2'||!a.filter(x=>typeof x==='string'&&x.startsWith('type=bind,')).every(x=>x.endsWith(',readonly')))return fail('command-containment');
 }else if(typeof command.executable!=='string'||!command.executable.replaceAll('\\','/').endsWith('/.runtime/node-v24.22.1-win-x64/node.exe')||typeof command.args[0]!=='string'||!command.args[0].replaceAll('\\','/').endsWith('/research/rea/scripts/rea.mjs'))return fail('command-launcher');
 let raw;try{raw=JSON.parse(stdoutBytes);}catch{return fail('stdout-not-json');}
 if(!raw||typeof raw!=='object'||raw.operation!==policy.operation||raw.provider?.id!==policy.provider||raw.parameters?.path!==selectedPath||raw.subject?.local_path!==selectedPath)return fail('evidence-context');
 if(!/^[a-f0-9]{64}$/.test(artifact?.sha256??'')||!uint(artifact?.bytes)||raw.subject?.digest?.sha256!==artifact.sha256)return fail('artifact-identity');
 const n=raw.normalized_result,identity=kind==='android-jni'?n?.apk:kind==='android-package'?null:n?.artifact;
 if(kind!=='android-package'&&(!identity||identity.path!==selectedPath||identity.sha256!==artifact.sha256||(kind!=='android-jni'&&identity.bytes!==artifact.bytes)))return fail('normalized-identity');
 const task=policy.predicate(raw,expected);return{ok:task,binding:true,task,reason:task?null:'selected-typed-task-missing'};
}

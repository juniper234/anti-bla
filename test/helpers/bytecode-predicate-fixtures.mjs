// Independently authored minimal provider envelopes for predicate unit tests.
// These are typed contract controls, not real artifacts, provider observations or
// recovery trials. They read no scratch files and execute no research tools.
import {createHash} from 'node:crypto';
const sha=b=>createHash('sha256').update(b).digest('hex');
export function independentPredicateCases(){const cases=[];
 for(const [n,amount,selector]of [[1,11,'11223344'],[2,13,'55667788'],[3,17,'99aabbcc']]){
  const seed=`bytecode-independent-${n}-20261030`,expected={selector:'0x'+selector,bytecodeOffset:20,sourceIp:'192.0.2.11',destinationIp:'198.51.100.9',sourcePort:'42123',frameNumber:'1',payloadHex:Buffer.from(`owned-udp-${n}-amount-${amount}`).toString('hex'),packageName:'org.antibla.owned',className:'OwnedFixture',methodName:'nativeOwned',descriptor:'(I)I',dexEntry:'classes.dex',abi:'arm64-v8a'};
  for(const kind of ['evm','pcap','android-package','android-jni'])for(const variant of kind==='evm'||kind==='pcap'?['clean','protected','normal_control']:['protected']){
   const linux=kind==='evm'||kind==='pcap',name=variant+'.'+(linux?kind:'apk'),artifactBytes=Buffer.from('independent unit carrier '+seed+' '+kind+' '+variant+' '+selector),selectedPath=linux?'/fixtures/'+seed+'/'+name:'C:/owned/'+seed+'/'+name,artifact={path:'C:/owned/'+seed+'/'+name,bytes:artifactBytes.length,sha256:sha(artifactBytes)};
   const operation={evm:'inspect_evm_interface',pcap:'inspect_packet_capture','android-package':'inspect_android_package','android-jni':'inspect_android_jni_bindings'}[kind],provider={id:linux?(kind==='evm'?'evmole-interface':'tshark-capture'):'jadx'},identity={path:selectedPath,sha256:artifact.sha256,bytes:artifact.bytes};
   let normalized_result;
   if(kind==='evm')normalized_result={artifact:identity,bytecode:{hex:Buffer.from('independent carrier '+selector).toString('hex')+selector},functions:[{selector:'0x'+selector,bytecode_offset:20,dispatch:'abi'}]};
   if(kind==='pcap')normalized_result={artifact:identity,selection:{fields:['ip.src','ip.dst','udp.srcport','data.data'],display_filter:'udp.srcport == 42123',packet_limit:null,match_offset:0,match_limit:1},packets:[{'frame.number':['1'],'ip.src':['192.0.2.11'],'ip.dst':['198.51.100.9'],'udp.srcport':['42123'],'data.data':[expected.payloadHex]}],read_scope:'to-eof',output_window:{returned_packets:1,matching_packets:1,has_more:false}};
   if(kind==='android-package')normalized_result={package_name:'org.antibla.owned',manifest:{status:'complete',text:'<manifest package="org.antibla.owned"><application /></manifest>'}};
   if(kind==='android-jni'){const id='owned-native-declaration-'+seed;normalized_result={apk:identity,native_inventory:{scope:'apk-root-dex-declarations',coverage:{status:'complete',dex_entries:1,examined_dex_entries:1,examined_classes:1,examined_methods:3},unknowns:[]},library_inventory:{status:'complete',selected_libraries:1},declarations:[{declaration_id:id,class_name:'OwnedFixture',method_name:'nativeOwned',descriptor:'(I)I',dex_entry:'classes.dex'}],selected_declaration_ids:[id],bindings:[{declaration_id:id,abi:'arm64-v8a',status:'unmatched',coverage:'complete',candidate_ids:[],unknowns:[]}],candidates:[],libraries:[{abi:'arm64-v8a',failure:null,coverage:{status:'complete',exports_status:'complete',tables_status:'complete',relocations_status:'complete'}}]};}
   const raw={operation,provider,parameters:{path:selectedPath},subject:{local_path:selectedPath,digest:{sha256:artifact.sha256}},normalized_result,raw_result:{functions:kind==='evm'?[{selector,bytecodeOffset:20}]:[]}},stdoutBytes=Buffer.from(JSON.stringify(raw)),cli=operation.replaceAll('_','-');
   const args=linux?['run','--rm','--network','none','--read-only','--user','65534:65534','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','128','--memory','1536m','--cpus','2','--tmpfs','/tmp:rw,nosuid,nodev,size=768m','--mount','type=bind,src=C:/owned,dst=/fixtures,readonly','unit-image','node','/rea/scripts/rea.mjs',cli,selectedPath]:['C:/owned/research/rea/scripts/rea.mjs',cli,selectedPath];
   const command={id:`unit-${n}-${kind}-${variant}`,executable:linux?'docker':'C:/owned/.runtime/node-v24.22.1-win-x64/node.exe',args,exit_code:0,timed_out:false,signal:null,stdout:{path:'C:/owned/unit.stdout',bytes:stdoutBytes.length,sha256:sha(stdoutBytes)}};
   const reference={command_id:command.id,exit_code:0,timed_out:false,stdout:{...command.stdout}};
   cases.push({kind,seed,variant,expected,raw,context:{command,reference,stdoutBytes,artifact,selectedPath}});
  }
 }
 return cases;
}

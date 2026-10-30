import test from 'node:test';
import assert from 'node:assert/strict';
import * as taskPredicates from './helpers/bytecode-predicates.mjs';
import {independentPredicateCases} from './helpers/bytecode-predicate-fixtures.mjs';
import {createHash} from 'node:crypto';
const {hasEvmTask,hasPacketTask,hasAndroidPackageTask,hasJniTask,evaluateBoundTask}=taskPredicates;
const bytecodeSha=b=>createHash('sha256').update(b).digest('hex');

const cases=independentPredicateCases(),predicates={evm:hasEvmTask,pcap:hasPacketTask,'android-package':hasAndroidPackageTask,'android-jni':hasJniTask};
const primary=cases.filter(c=>c.variant==='protected');
for(const c of primary){test(`I1 control ${c.kind} ${c.seed}`,()=>{
 const raw=structuredClone(c.raw);
 if(c.kind==='evm'){raw.normalized_result.functions=[];raw.raw_result.functions=[];}
 if(c.kind==='pcap'){raw.normalized_result.packets[0]['ip.src']=['203.0.113.100'];raw.normalized_result.packets[0]['udp.srcport']=['9'];}
 if(c.kind==='android-package')raw.normalized_result.package_name='org.wrong.package';
 if(c.kind==='android-jni')raw.normalized_result.bindings=[];
 assert.equal(predicates[c.kind](raw,c.expected),false,'mutated typed task must not pass from carrier/XML/payload text or empty collections');
});}
for(const c of cases)test(`independent typed positive ${c.kind} ${c.seed} ${c.variant}`,()=>assert.equal(predicates[c.kind](c.raw,c.expected),true));
const mutations={
 evm:[['missing functions',n=>delete n.functions],['wrong offset',n=>n.functions[0].bytecode_offset=21],['string offset',n=>n.functions[0].bytecode_offset='20'],['wrong selector',n=>n.functions[0].selector='0xdeadbeef'],['duplicate selector',n=>n.functions.push(structuredClone(n.functions[0]))]],
 pcap:[['wrong destination',n=>n.packets[0]['ip.dst']=['203.0.113.8']],['wrong port',n=>n.packets[0]['udp.srcport']=['53']],['missing address',n=>delete n.packets[0]['ip.src']],['missing payload',n=>delete n.packets[0]['data.data']],['empty packets',n=>n.packets=[]],['repeated address',n=>n.packets[0]['ip.src'].push('192.0.2.11')],['missing window',n=>delete n.output_window],['partial output',n=>n.output_window.has_more=true],['wrong returned count',n=>n.output_window.returned_packets=0],['partial input',n=>n.read_scope='up-to-input-packet-limit'],['missing field selection',n=>n.selection.fields=['data.data']],['wrong frame',n=>n.packets[0]['frame.number']=['2']]],
 'android-package':[['missing package',n=>delete n.package_name],['partial manifest',n=>n.manifest.status='partial'],['missing manifest',n=>delete n.manifest]],
 'android-jni':[['missing binding',n=>delete n.bindings],['empty declarations',n=>n.declarations=[]],['partial declarations',n=>n.native_inventory.coverage.status='partial'],['unexamined DEX',n=>n.native_inventory.coverage.examined_dex_entries=0],['wrong native method',n=>n.declarations[0].method_name='other'],['wrong descriptor',n=>n.declarations[0].descriptor='()V'],['missing selected ID',n=>n.selected_declaration_ids=[]],['wrong binding ID',n=>n.bindings[0].declaration_id='different'],['partial binding',n=>n.bindings[0].coverage='partial'],['unknown binding',n=>n.bindings[0].status='unknown'],['false matched binding',n=>n.bindings[0].status='matched'],['false candidate',n=>n.candidates=[{candidate_id:'false'}]],['candidate reference',n=>n.bindings[0].candidate_ids=['false']],['missing candidates',n=>delete n.candidates],['partial library inventory',n=>n.library_inventory.status='partial'],['empty libraries',n=>n.libraries=[]],['partial library facts',n=>n.libraries[0].coverage.exports_status='partial']],
};
for(const [kind,rows]of Object.entries(mutations)){const c=primary.find(c=>c.kind===kind);for(const [label,mutate]of rows)test(`fail closed ${kind}: ${label}`,()=>{const raw=structuredClone(c.raw);mutate(raw.normalized_result);assert.equal(predicates[kind](raw,c.expected),false);});}
for(const kind of Object.keys(predicates))for(const [label,raw]of [['missing envelope',undefined],['null envelope',null],['missing normalized result',{}],['null normalized result',{normalized_result:null}]])test(`missing typed envelope ${kind}: ${label}`,()=>assert.equal(predicates[kind](raw,primary.find(c=>c.kind===kind).expected),false));
for(const [label,field]of [['null declaration','declarations'],['null binding','bindings'],['null library','libraries']])test('JNI collection fails closed: '+label,()=>{const c=primary.find(c=>c.kind==='android-jni'),raw=structuredClone(c.raw);raw.normalized_result[field]=[null];assert.equal(hasJniTask(raw,c.expected),false);});
for(const c of cases)test(`bound synthetic output ${c.kind} ${c.seed} ${c.variant}`,()=>assert.equal(evaluateBoundTask(c.kind,c.expected,c.context).ok,true));
const bound=primary.find(c=>c.kind==='evm');
for(const [label,change]of [
 ['nonzero exit',c=>c.command.exit_code=1],['timeout',c=>c.command.timed_out=true],['wrong stdout hash',c=>c.command.stdout.sha256='0'.repeat(64)],['wrong stdout length',c=>c.command.stdout.bytes--],['wrong artifact digest',c=>c.artifact.sha256='0'.repeat(64)],['wrong artifact length',c=>c.artifact.bytes++],['wrong selected path',c=>c.selectedPath+='.other'],['wrong command path',c=>c.command.args[c.command.args.indexOf('inspect-evm-interface')+1]+='.other'],['reference mismatch',c=>c.reference.command_id='wrong'],['reference hash mismatch',c=>c.reference.stdout.sha256='0'.repeat(64)],['uncontained Docker',c=>c.command.args[c.command.args.indexOf('--network')+1]='bridge'],
])test('command/context fails closed: '+label,()=>{const context={...bound.context,command:structuredClone(bound.context.command),reference:structuredClone(bound.context.reference),artifact:structuredClone(bound.context.artifact)};change(context);assert.equal(evaluateBoundTask(bound.kind,bound.expected,context).ok,false);});
for(const [label,change]of [['wrong operation',r=>r.operation='inspect_artifact'],['wrong provider',r=>r.provider.id='other'],['wrong subject hash',r=>r.subject.digest.sha256='0'.repeat(64)],['wrong evidence path',r=>r.parameters.path+='.other'],['missing normalized result',r=>delete r.normalized_result]])test('envelope fails closed: '+label,()=>{const raw=structuredClone(bound.raw);change(raw);const stdoutBytes=Buffer.from(JSON.stringify(raw));const command=structuredClone(bound.context.command),reference=structuredClone(bound.context.reference);command.stdout.sha256=reference.stdout.sha256=bytecodeSha(stdoutBytes);command.stdout.bytes=reference.stdout.bytes=stdoutBytes.length;assert.equal(evaluateBoundTask(bound.kind,bound.expected,{...bound.context,stdoutBytes,command,reference}).ok,false);});

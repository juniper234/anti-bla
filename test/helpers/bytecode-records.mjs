// Retained own fixture evidence loader. No targets/providers execute here.
import {readFileSync} from 'node:fs';
import {resolve,join,dirname,basename} from 'node:path';
import {createHash} from 'node:crypto';
export const bytecodeRoot=resolve(import.meta.dirname,'../..');
export const bytecodeHistoricalReports=[
 'reports/C6-bytecode-2026-10-30T04-17-50-323Z.json',
 'reports/C6-bytecode-2026-10-30T04-18-41-659Z.json',
 'reports/C6-bytecode-2026-10-30T04-20-33-440Z.json',
 'reports/C6-bytecode-2026-10-30T04-22-43-182Z.json',
 'reports/C6-bytecode-2026-10-30T04-26-10-375Z.json',
 'reports/C6-bytecode-frida-2026-10-30T04-33-07-089Z.json',
];
export const bytecodeSha=b=>createHash('sha256').update(b).digest('hex');
export function bytecodeIdentity(path){const b=readFileSync(path);return{path,sha256:bytecodeSha(b),bytes:b.length};}
export function expectedBytecodeSeed(seed){const m=/^bytecode-independent-([123])-20261030$/.exec(seed);if(!m)throw new Error('Unknown owned seed');const n=Number(m[1]);return{n,multiplier:[3,5,7][n-1],amount:[11,13,17][n-1],selector:'0x'+['11223344','55667788','99aabbcc'][n-1],bytecodeOffset:20,sourceIp:'192.0.2.11',destinationIp:'198.51.100.9',sourcePort:'42123',frameNumber:'1',payloadHex:Buffer.from(`owned-udp-${n}-amount-${[11,13,17][n-1]}`).toString('hex'),packageName:'org.antibla.owned',className:'OwnedFixture',methodName:'nativeOwned',descriptor:'(I)I',dexEntry:'classes.dex',abi:'arm64-v8a',endpoint:'/api/owned/'+seed};}
export function retainedBytecodeContext(report,reference,artifactPath,selectedPath){
 const command=report.commands.find(c=>c.id===reference?.command_id);if(!command)throw new Error('Referenced command missing');
 const stdoutBytes=readFileSync(command.stdout.path),raw=JSON.parse(stdoutBytes);
 const independentlySelectedPath=command.executable==='docker'?'/fixtures/'+basename(dirname(artifactPath))+'/'+basename(artifactPath):artifactPath;
 return{command,reference,stdoutBytes,artifact:bytecodeIdentity(artifactPath),selectedPath:selectedPath??independentlySelectedPath,raw};
}
export function retainedRecordTaskCases(report,record,meta={}){const cases=[],expected=expectedBytecodeSeed(record.seed),base={...meta,seed:record.seed,expected};
   if(record.family==='evm'||record.family==='pcap')for(const variant of ['clean','protected','normal_control']){const ext=record.family==='evm'?'evm':'pcap',artifactPath=variant==='clean'?record.emission.input.path:variant==='protected'?record.emission.output.path:join(dirname(record.emission.input.path),'benign.'+ext);const context=retainedBytecodeContext(report,record[variant],artifactPath);cases.push({...base,kind:record.family,variant,raw:context.raw,context});}
   if(record.family==='android-authoritative-sidecars')for(const [kind,key]of [['android-package','manifest'],['android-jni','jni']]){const context=retainedBytecodeContext(report,record.protected[key],record.origin.apk.path);cases.push({...base,kind,variant:'protected',raw:context.raw,context});}
 return cases;
}
export function retainedBytecodeTaskCases(){const cases=[];
 for(const relative of bytecodeHistoricalReports){const reportPath=join(bytecodeRoot,relative),report=JSON.parse(readFileSync(reportPath));
  report.records.forEach((record,recordIndex)=>cases.push(...retainedRecordTaskCases(report,record,{reportPath,recordIndex})));
 }
 return cases;
}

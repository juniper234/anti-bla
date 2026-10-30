// Trusted, independently authored qualification fixture constructors. Never executes input.
export const toolsDockerfile = `FROM node@sha256:d862bb5d082c5ae0210ac07e8c0344cb8cf7bef6d78e9b8c50c179da923108ea
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends erlang-base erlang-dev tshark && dpkg-query -W erlang-base erlang-dev tshark libwireshark-data && rm -rf /var/lib/apt/lists/*
`;
export function evmFixture(selector, value) {
  // Independently authored legacy runtime dispatcher, no RPC or deployment.
  // 0x14 is the JUMPDEST; every branch terminates in RETURN or REVERT.
  return Buffer.from(`60003560e01c8063${selector}14601457600080fd5b60${value.toString(16).padStart(2,'0')}60005260206000f3`, 'hex');
}
export function pcapFixture(label, port=42123) {
  const payload=Buffer.from(label), g=Buffer.alloc(24), r=Buffer.alloc(16), eth=Buffer.alloc(14),ip=Buffer.alloc(20),udp=Buffer.alloc(8);
  g.writeUInt32LE(0xa1b2c3d4);g.writeUInt16LE(2,4);g.writeUInt16LE(4,6);g.writeUInt32LE(65535,16);g.writeUInt32LE(1,20);
  eth.writeUInt16BE(0x0800,12);ip[0]=0x45;ip.writeUInt16BE(28+payload.length,2);ip[8]=64;ip[9]=17;ip.set([192,0,2,11],12);ip.set([198,51,100,9],16);
  let sum=0;for(let i=0;i<20;i+=2)sum+=ip.readUInt16BE(i);while(sum>65535)sum=(sum&65535)+(sum>>>16);ip.writeUInt16BE((~sum)&65535,10);
  udp.writeUInt16BE(port,0);udp.writeUInt16BE(port+1,2);udp.writeUInt16BE(8+payload.length,4);
  const frame=Buffer.concat([eth,ip,udp,payload]);r.writeUInt32LE(1700000000);r.writeUInt32LE(frame.length,8);r.writeUInt32LE(frame.length,12);return Buffer.concat([g,r,frame]);
}
export function beamWithOrdinaryChunks(bytes, total=260) {
  // Qualification control only: append valid neutral IFF chunks to genuine erlc
  // bytes without replacing atom/table/Code data or assigning decoy semantics.
  const end=bytes.readUInt32BE(4)+8;let at=12,count=0;
  while(at<end){if(at+8>end)throw new Error('control chunk header');const n=bytes.readUInt32BE(at+4);at+=8+n+((4-n%4)%4);if(at>end)throw new Error('control chunk extent');count++;}
  const parts=[bytes.subarray(0,end)];for(let i=count;i<total;i++){const data=Buffer.from(('ordinary provenance record '+i+' ').repeat(100)),header=Buffer.alloc(8);header.write('Note');header.writeUInt32BE(data.length,4);parts.push(header,data,Buffer.alloc((4-data.length%4)%4));}
  const result=Buffer.concat(parts);result.writeUInt32BE(result.length-8,4);return result;
}
export const packagePython = String.raw`import sys,zipfile,json
from pathlib import Path
p=Path(sys.argv[1]); dex=Path(sys.argv[2]); manifest=sys.argv[3]
with zipfile.ZipFile(p,'w',compression=zipfile.ZIP_STORED) as z:
 z.writestr('classes.dex',dex.read_bytes());z.writestr('AndroidManifest.xml',manifest)
 for n in range(int(sys.argv[4])):z.writestr('assets/documentation/'+str(n)+'.txt','ordinary reference '*100)
 if len(sys.argv)>5:
  z.writestr('assets/bla-shield/mapping.txt',Path(sys.argv[5]).read_bytes())
  z.writestr('lib/arm64-v8a/libbla_enclave_jni.so',Path(sys.argv[6]).read_bytes())
  z.writestr('assets/bla-shield/AndroidManifest.xml',Path(sys.argv[7]).read_bytes())
print(json.dumps({'unsigned':True,'manifest_encoding':'text XML','installability':'UNKNOWN','compiler_artifact':str(dex)}))
`;
export const cdpProbe = String.raw`import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {readFileSync} from 'node:fs';
const path=process.argv[2];
if(!/^\/fixtures\/[a-zA-Z0-9_./-]+\.mjs$/.test(path))throw new Error('fixed fixture path');
// Runtime.evaluate has no Node dynamic-import callback. Define the trusted loader
// in the real ESM launcher, then call it over CDP so the actual target is loaded.
const launcher='globalThis.__antiBlaLoadOwnFixture=()=>import('+JSON.stringify('file://'+path)+');setInterval(()=>{},1000)';
const child=spawn(process.execPath,['--inspect=127.0.0.1:0','--input-type=module','-e',launcher],{stdio:['ignore','pipe','pipe']});
let stderr='';const endpoint=await new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(new Error('inspector startup timeout')),10000);child.stderr.on('data',b=>{stderr+=b;const m=/ws:\/\/127\.0\.0\.1:\d+\/[a-z0-9-]+/.exec(stderr);if(m){clearTimeout(timer);resolve(m[0]);}});child.on('exit',c=>{clearTimeout(timer);reject(new Error('target exited '+c));});});
let ws;
try{
 ws=new WebSocket(endpoint);await once(ws,'open');let id=0;const pending=new Map();
 ws.addEventListener('message',event=>{const v=JSON.parse(event.data);if(v.id){const p=pending.get(v.id);pending.delete(v.id);v.error?p.reject(new Error(JSON.stringify(v.error))):p.resolve(v.result);}});
 const send=(method,params={})=>new Promise((resolve,reject)=>{const key=++id;pending.set(key,{resolve,reject});ws.send(JSON.stringify({id:key,method,params}));});
 await send('Runtime.enable');await send('Profiler.enable');await send('Profiler.startPreciseCoverage',{callCount:true,detailed:true});
 const expression='(async()=>{ const m=await globalThis.__antiBlaLoadOwnFixture(); const calls=[]; m.register({post:(...args)=>calls.push(args)}); const shadows=[]; for(const key of Object.getOwnPropertyNames(globalThis)){const d=Object.getOwnPropertyDescriptor(globalThis,key);if(d&&d.get){try{const v=d.get.call(globalThis);if(v&&v.classification==="decorative-deception-signal")shadows.push({key,classification:v.classification,inspectorObserved:v.inspectorObserved});}catch{}}} return {calls,shadows}; })()';
 const evaluated=await send('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true});
 const coverage=await send('Profiler.takePreciseCoverage');
 const source=readFileSync(path,'utf8');
 const scripts=coverage.result.filter(s=>s.url==='file://'+path).map(s=>({...s,functions:s.functions.map(f=>({...f,source_excerpt:source.slice(f.ranges[0].startOffset,Math.min(f.ranges[0].endOffset,f.ranges[0].startOffset+160))}))}));
 console.log(JSON.stringify({schema:'anti-bla.cdp-owned-fixture/1',transport:'actual loopback CDP WebSocket inside network-none container',target:path,evaluated,coverage:scripts,stderr,target_executed:true}));
 if(evaluated.exceptionDetails)process.exitCode=2;
}finally{if(ws)ws.close();child.kill('SIGTERM');await once(child,'exit');}
`;

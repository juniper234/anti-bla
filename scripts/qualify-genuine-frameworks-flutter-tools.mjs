import { readFile,writeFile,mkdir,statfs } from 'node:fs/promises';
import { createWriteStream } from 'node:fs';
import { createHash } from 'node:crypto';
import { Readable,Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
const root=process.cwd(),runId=new Date().toISOString().replace(/[:.]/g,'-'),report={schema:'anti-bla.flutter-prerequisites/1',runId,startedAt:new Date().toISOString(),invocation:[process.execPath,...process.argv.slice(1)],targetExecution:false,commands:[],downloads:[],peakRssBytes:null,cpuSeconds:null,tokens:null,cost:null},reportPath=resolve(root,`reports/C5-genuine-flutter-tools-${runId}.json`);
const save=()=>writeFile(reportPath,JSON.stringify(report,null,2));
try{
 const disk=await statfs(root);report.diskBefore={freeBytes:disk.bavail*disk.bsize};if(report.diskBefore.freeBytes<7*1024**3)throw Error('Less than7GiB free; no cleanup authorized');
 const url='https://storage.googleapis.com/flutter_infra_release/releases/releases_linux.json',r=await fetch(url),raw=Buffer.from(await r.arrayBuffer());if(!r.ok)throw Error(`metadata HTTP${r.status}`);const meta=JSON.parse(raw),selected=meta.releases.find(x=>x.version==='3.35.0'&&x.channel==='stable'&&x.dart_sdk_arch==='x64');if(!selected)throw Error('Missing pinned release');report.metadata={url,sha256:createHash('sha256').update(raw).digest('hex'),selected};
 const path=resolve(root,'.tools/frameworks/downloads/flutter_linux_3.35.0-stable.tar.xz'),assetUrl=meta.base_url+'/'+selected.archive,start=performance.now(),startedAt=new Date().toISOString(),res=await fetch(assetUrl);if(!res.ok)throw Error(`archive HTTP${res.status}`);let bytes=0;const hash=createHash('sha256');await pipeline(Readable.fromWeb(res.body),new Transform({transform(chunk,enc,cb){bytes+=chunk.length;hash.update(chunk);cb(null,chunk)}}),createWriteStream(path,{flags:'wx'}));const actual=hash.digest('hex');report.downloads.push({url:assetUrl,path,startedAt,wallMs:performance.now()-start,bytes,expectedSha256:selected.sha256,actualSha256:actual,verified:actual===selected.sha256});if(actual!==selected.sha256)throw Error('SHA256 mismatch');report.status='VERIFIED_OFFICIAL_SDK_ARCHIVE';
}catch(e){report.status='FAILED';report.error=String(e);process.exitCode=1;}finally{report.completedAt=new Date().toISOString();await save();console.log(JSON.stringify({reportPath,status:report.status,error:report.error}));}

import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
import { spawn } from 'node:child_process';
import { performance } from 'node:perf_hooks';
const root=process.cwd(), local=resolve(root,'.tools/frameworks'), downloads=resolve(local,'downloads');
await mkdir(downloads,{recursive:true});
await mkdir(resolve(root,'scratch/frameworks'),{recursive:true});
const runId=new Date().toISOString().replace(/[:.]/g,'-');
const report={schema:'anti-bla.genuine-framework-tools/1',runId,startedAt:new Date().toISOString(),downloads:[],commands:[],targetExecution:false,globalInstall:false};
const digest=(b,alg='sha256',enc='hex')=>createHash(alg).update(b).digest(enc);
async function save(){await writeFile(resolve(root,`reports/C5-genuine-tools-${runId}.json`),JSON.stringify(report,null,2));}
async function fetchFile(url,name,expected,algorithm='sha256',encoding='hex'){
 const start=performance.now(),startedAt=new Date().toISOString(),res=await fetch(url); if(!res.ok)throw Error(`${res.status} ${url}`);
 const bytes=Buffer.from(await res.arrayBuffer()),path=resolve(downloads,name),actual=digest(bytes,algorithm,encoding);
 await writeFile(path,bytes); report.downloads.push({url,path,startedAt,wallMs:performance.now()-start,bytes:bytes.length,algorithm,expected,actual,verified:expected===null?null:actual===expected}); await save();
 if(expected!==null&&actual!==expected)throw Error(`Integrity mismatch ${name}`); return bytes;
}
async function cmd(id,exe,args){const start=performance.now(),startedAt=new Date().toISOString(),o=[],e=[],child=spawn(exe,args,{cwd:root,windowsHide:true,stdio:['ignore','pipe','pipe']});child.stdout.on('data',b=>o.push(b));child.stderr.on('data',b=>e.push(b));const exitCode=await new Promise(r=>{child.on('error',x=>{e.push(Buffer.from(String(x)));r(null)});child.on('close',r)});const stdout=Buffer.concat(o),stderr=Buffer.concat(e);const stdoutPath=resolve(root,`scratch/frameworks/${runId}-${id}.stdout.log`),stderrPath=resolve(root,`scratch/frameworks/${runId}-${id}.stderr.log`);await writeFile(stdoutPath,stdout);await writeFile(stderrPath,stderr);report.commands.push({command:[exe,...args],startedAt,wallMs:performance.now()-start,exitCode,stdoutPath,stderrPath,stdoutSha256:digest(stdout),stderrSha256:digest(stderr),cpuSeconds:null,peakRssBytes:null});await save();if(exitCode!==0)throw Error(`${id} exit ${exitCode}`);}
try {
 const checks=await fetchFile('https://github.com/electron/electron/releases/download/v39.0.0/SHASUMS256.txt','electron-v39.0.0-SHASUMS256.txt','05378316498d150967d53b9d0ef6c9de6b7d106308a04d1fb060d4ca0d2309f3');
 const asset='electron-v39.0.0-win32-x64.zip',match=checks.toString().split(/\r?\n/).map(s=>s.trim().split(/\s+/)).find(x=>x[1]?.replace(/^\*/,'')===asset);if(!match)throw Error('No checksum');
 await fetchFile(`https://github.com/electron/electron/releases/download/v39.0.0/${asset}`,asset,match[0]);
 for(const [name,version] of [['@electron/fuses','2.0.0'],['@electron/asar','4.0.1'],['resedit','2.0.3']]){
  const m=await fetchFile(`https://registry.npmjs.org/${name}/${version}`,`${name.replaceAll('/','-').replace('@','')}-${version}.metadata.json`,null);const meta=JSON.parse(m);if(!meta.dist?.integrity?.startsWith('sha512-'))throw Error('Missing npm SHA512');
  await fetchFile(meta.dist.tarball,`${name.replaceAll('/','-').replace('@','')}-${version}.tgz`,meta.dist.integrity.slice(7),'sha512','base64');
  report.downloads.at(-1).license=meta.license;report.downloads.at(-1).repository=meta.repository;
 }
 await cmd('install',resolve(root,'.runtime/node-v24.22.1-win-x64/node.exe'),[resolve(root,'.runtime/node-v24.22.1-win-x64/node_modules/npm/bin/npm-cli.js'),'install','--prefix',local,'--cache',resolve(root,'.runtime/frameworks/npm-cache'),'--ignore-scripts','--no-audit','--no-fund','--save-exact',resolve(downloads,'electron-fuses-2.0.0.tgz'),resolve(downloads,'electron-asar-4.0.1.tgz'),resolve(downloads,'resedit-2.0.3.tgz')]);
 await cmd('extract', 'powershell.exe',['-NoProfile','-Command',`Expand-Archive -LiteralPath '${resolve(downloads,asset)}' -DestinationPath '${resolve(local,'electron-v39.0.0-win32-x64')}'`]);
 report.packageLockSha256=digest(await readFile(resolve(local,'package-lock.json')));report.status='VERIFIED_DOWNLOADS_AND_LOCAL_INSTALL';
}catch(e){report.status='FAILED';report.error=String(e);process.exitCode=1;}finally{report.completedAt=new Date().toISOString();await save();console.log(JSON.stringify({status:report.status,report:`reports/C5-genuine-tools-${runId}.json`,error:report.error}));}

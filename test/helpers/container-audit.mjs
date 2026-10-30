// Re-audit retained qualification evidence, not target programs. This snapshot
// deliberately names reports rather than silently selecting a newer/greener run.
import { readFileSync,writeFileSync,mkdirSync,existsSync,statSync } from 'node:fs';
import { resolve,join } from 'node:path';
import { createHash } from 'node:crypto';
import { auditContainerJavaScript } from './container-predicates.mjs';
const root=resolve(import.meta.dirname,'../..'),sha=b=>createHash('sha256').update(b).digest('hex');
const selection=[
 ['C6-containers-2026-10-30T03-26-09-988Z.json',['apple-plist-xml','apple-plist-binary','sourcemap','jvm-class','dotnet-managed','zip','android-apk','html','directory','python-source','python-pyc']],
];
const errors=[],records=[],sourceReports=[],commandArtifacts=[];
const json=p=>JSON.parse(readFileSync(p,'utf8'));
function check(condition,message){if(!condition)errors.push(message);return!!condition;}
function artifact(p,expected,kind){const absolute=resolve(p);if(!check(absolute.toLowerCase().startsWith((root+'\\').toLowerCase()),kind+' outside project'))return false;
 const actual=existsSync(absolute)&&statSync(absolute).isFile()?sha(readFileSync(absolute)):null;
 return check(actual===expected,kind+' missing or changed: '+p);
}
function output(ref){return json(ref.stdout.path);}
function selectedAndroid(ref,m,a){const n=output(ref)?.normalized_result;return ref.exit_code===0&&n?.class_name==='defpackage.OwnedFixture'&&n?.method?.name==='score'&&n?.method?.dex_descriptor==='(I)I'&&n?.body_status==='available'&&n?.source?.status==='complete'&&new RegExp(`return \\(i \\* ${m}\\) \\+ ${a};`).test(n.source.text);}
for(const [file,families]of selection){const p=join(root,'reports',file),r=json(p);sourceReports.push({path:p,sha256:sha(readFileSync(p)),selected_families:families});
 check(r.status==='MEASURED_REVIEW_PENDING',file+' is incomplete');
 check(r.pins.bla==='b2d643600774d62e562081129e55b13b0d9e8a80'&&r.pins.rea==='317bf3fe235e655b2d752d3be261cc0da7d00f2b',file+' source pins');
 for(const c of r.commands)for(const stream of ['stdout','stderr']){const v=c[stream];const ok=artifact(v.path,v.sha256,'retained '+stream);commandArtifacts.push({report:file,command_id:c.id,stream,sha256:v.sha256,unchanged:ok});}
 for(const row of r.records.filter(x=>families.includes(x.family))){
  const retained=[];for(const x of [row.emission?.input,row.emission?.output,row.second?.input,row.second?.output].filter(x=>x?.sha256))retained.push({path:x.path,sha256:x.sha256,unchanged:artifact(x.path,x.sha256,'original artifact')});
  const base={family:row.family,seed:row.seed,source_report:file,originals:retained,assertions:row.assertions,source_ruling:row.ruling,scope:row.task};
  if(row.family==='android-apk'){
   const {multiplier:m,addend:a}=row.expected;base.typed_selected_method={clean:selectedAndroid(row.clean,m,a),protected:selectedAndroid(row.protected,m,a),normal:selectedAndroid(row.normal_control.command,m,a)};
   check(Object.values(base.typed_selected_method).every(Boolean),'typed APK body '+row.seed);
  }
  if(row.family==='python-pyc'){
   const h=row.anti_handoff,pr=row.official_protected,derived=readFileSync(h.derivative.path),original=readFileSync(row.emission.output.path),n=output(h.rea)?.normalized_result,score=n?.code_objects?.filter(c=>c.name==='score')??[];
   base.handoff={original_rea_refused:row.source_rea.protected.exit_code===1,anti_byte_view_ok:h.anti.exit_code===0,source_range_equals_protected_prefix:derived.equals(original.subarray(0,16+pr.root_marshal_range.length)),rea_re_admitted:h.rea.exit_code===0,selected_code_sha256_matches:score.length===1&&score[0].bytecode.sha256===pr.co_code_sha256,opaque_tail_bytes:pr.opaque_tail_bytes};
   check(Object.values(base.handoff).filter(x=>typeof x==='boolean').every(Boolean),'PYC handoff '+row.seed);
  }
  if(['html','directory'].includes(row.family)){
   const recomputed=auditContainerJavaScript(row,r.commands);
   base.stored_assertions_not_revalidated=base.assertions;delete base.assertions;
   base.recomputed_js=recomputed;
   base.selected_rea={clean:recomputed.selected_rea.clean?.selected_assertion??false,protected:recomputed.selected_rea.protected?.selected_assertion??false,handoff:recomputed.selected_rea.handoff?.selected_assertion??false,coverage:recomputed.selected_rea.handoff?.coverage??null};
   check(recomputed.errors.length===0,'JS selected call handoff '+row.family+' '+row.seed+': '+recomputed.errors.join('; '));
  }
  if(row.family==='apple-plist-binary')check(row.assertions.clean_task&&!row.assertions.protected_task,'binary plist expected UNKNOWN '+row.seed);
  else if(row.family==='sourcemap')check(row.assertions.distinct_originals&&row.assertions.identical_protected&&row.assertions.original_token_absent,'source map non-injective replacement '+row.seed);
  else if(!['html','directory'].includes(row.family))check(Object.values(row.assertions).every(Boolean),'selected static assertions '+row.family+' '+row.seed);
  records.push(base);
 }
}
const counts=Object.fromEntries([...new Set(records.map(r=>r.family))].map(f=>[f,new Set(records.filter(r=>r.family===f).map(r=>r.seed)).size]));
check(records.length===33&&Object.values(counts).every(n=>n===3),'11 families need exactly three independent seeds');
const stamp=new Date().toISOString().replace(/[:.]/g,'-'),p=join(root,'reports',`C6-containers-audit-${stamp}.json`);
const earlier=['C6-containers-2026-10-30T03-15-45-198Z.json','C6-containers-2026-10-30T03-16-11-953Z.json','C6-containers-2026-10-30T03-16-11-964Z.json','C6-containers-audit-2026-10-30T03-23-37-409Z.json'].map(file=>({path:join(root,'reports',file),sha256:sha(readFileSync(join(root,'reports',file))),accepted_as_final_batch:false}));
const harness=['scripts/qualify-containers.mjs','test/helpers/container-python.mjs','test/helpers/container-audit.mjs','test/helpers/container-predicates.mjs'].map(file=>({path:join(root,file),sha256:sha(readFileSync(join(root,file))),scope:'source bytes at audit time'}));
const result={schema:'anti-bla.c6-containers-evidence-audit/1',recorded_utc:new Date().toISOString(),audit_source:'implementation-worker',status:errors.length?'ERROR':'STATIC_CHECKS_COMPLETE_REVIEW_PENDING',claim:'Evidence consistency and selected task assertions only. Not blind independent review or whole-C6 PASS.',counts,source_reports:sourceReports,retained_earlier_evidence:earlier,harness_source_at_audit:harness,command_artifacts:commandArtifacts,records,errors,resource_measurements:{peak_rss:null,cpu_seconds:null},target_executed:false};
writeFileSync(p,JSON.stringify(result,null,2));console.log(JSON.stringify({report:p,status:result.status,records:records.length,command_streams:commandArtifacts.length,counts,errors}));if(errors.length)process.exitCode=1;

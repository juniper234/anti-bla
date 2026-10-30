// Qualification-only predicates. Parse inert source; never invoke its functions.
import { readFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { createHash } from 'node:crypto';
import { parse } from '@babel/parser';
import traverseModule from '@babel/traverse';
const traverse=traverseModule.default??traverseModule;
const sha=b=>createHash('sha256').update(b).digest('hex');
const samePath=(a,b)=>typeof a==='string'&&typeof b==='string'&&resolve(a).toLowerCase()===resolve(b).toLowerCase();
const sameLocation=(a,b)=>!!a&&!!b&&a.start?.line===b.start?.line&&a.start?.column===b.start?.column&&a.end?.line===b.end?.line&&a.end?.column===b.end?.column;
const sameRange=(r,n,source)=>r?.utf16Start===n.start&&r?.utf16End===n.end&&r?.byteStart===Buffer.byteLength(source.slice(0,n.start))&&r?.byteEnd===Buffer.byteLength(source.slice(0,n.end));

function selectedCall(bytes){
 const source=bytes.toString('utf8'),ast=parse(source,{sourceType:'module'});
 let program;traverse(ast,{Program(p){program=p;p.stop();}});
 const exported=[];
 for(const statement of ast.program.body){
  if(statement.type!=='ExportNamedDeclaration'||statement.source)continue;
  if(statement.declaration?.type==='FunctionDeclaration'&&statement.declaration.id?.name==='register')exported.push(program.scope.getBinding('register'));
  for(const s of statement.specifiers??[])if(s.type==='ExportSpecifier'&&(s.exported.name??s.exported.value)==='register')exported.push(program.scope.getBinding(s.local.name));
 }
 if(exported.length!==1||!exported[0]?.constant)return null;
 let fn=exported[0].path;
 if(fn.isVariableDeclarator())fn=fn.get('init');
 if(!fn.isFunction()||fn.node.params[0]?.type!=='Identifier')return null;
 const parameter=fn.scope.getBinding(fn.node.params[0].name);
 if(!parameter?.constant)return null;
 const calls=[];
 fn.traverse({CallExpression(p){
  const c=p.node.callee;
  if(p.getFunctionParent()?.node!==fn.node||c.type!=='MemberExpression'||c.computed||c.object.type!=='Identifier'||c.property.type!=='Identifier'||c.property.name!=='post')return;
  if(p.scope.getBinding(c.object.name)!==parameter||!p.node.arguments[0]||p.node.arguments[0].type==='SpreadElement')return;
  calls.push(p.node);
 }});
 // These owned tasks select one call. Multiple candidates are ambiguous.
 return calls.length===1?{source,fn:fn.node,call:calls[0],arg:calls[0].arguments[0],sha256:sha(bytes)}:null;
}

export function antiSelected(report,value,bytes){
 try{
  if(!Buffer.isBuffer(bytes)||report?.status!=='OK'||report.source?.sha256!==sha(bytes)||report.source?.byteLength!==bytes.length)return false;
  const selected=selectedCall(bytes);if(!selected)return false;
  const roots=report.roots?.filter(r=>r.exportName==='register')??[];
  return roots.length===1&&sameRange(roots[0].range,selected.fn,selected.source)&&
   (report.facts?.some(f=>f.root==='register'&&f.kind==='call-argument'&&f.value===value&&sameRange(f.range,selected.arg,selected.source))??false);
 }catch{return false;}
}

export function reaSelected(command,value,sourcePath){
 const result={raw_status:null,coverage:null,provenance_ok:false,selected_assertion:false};
 try{
  if(command?.exit_code!==0||command.timed_out!==false||command.signal||command.error)return result;
  const args=command.args;
  if(!Array.isArray(args)||args[1]!=='analyze-javascript-application'||!samePath(sourcePath,join(args[2],'index.mjs')))return result;
  const raw=readFileSync(command.stdout.path);
  if(sha(raw)!==command.stdout.sha256||raw.length!==command.stdout.bytes)return result;
  const v=JSON.parse(raw.toString('utf8')),n=v?.normalized_result,g=n?.semantic_graph;
  result.raw_status=v?.status??null;result.coverage=g?.coverage?.status??null;
  if(!samePath(n?.input_path,args[2])||!samePath(v?.subject?.local_path,args[2])||!Array.isArray(g?.nodes))return result;
  const selected=selectedCall(readFileSync(sourcePath));
  // A source without the selected export/call cannot satisfy the task.
  if(!selected){result.provenance_ok=true;return result;}
  const matches=(node,syntax)=>node.identity?.artifact_sha256===selected.sha256&&node.identity?.module_path==='index.mjs'&&sameLocation(node.identity.source_range,syntax.loc)&&node.evidence?.location?.value?.source==='index.mjs'&&sameLocation(node.evidence.location.value,syntax.loc);
  const functions=g.nodes.filter(node=>node.kind==='function'&&matches(node,selected.fn));
  const sourceRecorded=n.graph?.nodes?.some(node=>node.kind==='javascript-asset'&&node.observations?.some(o=>o.properties?.path==='index.mjs'&&o.evidence?.artifact?.sha256===selected.sha256));
  if(functions.length!==1||!sourceRecorded)return result;
  result.provenance_ok=true;
  const calls=g.nodes.filter(node=>node.kind==='call-site'&&node.function_node_id===functions[0].node_id&&matches(node,selected.call));
  result.selected_assertion=calls.length===1&&(calls[0].properties?.arguments?.some(a=>a.index===0&&a.value===value&&sameLocation(a.source_range,selected.arg.loc))??false);
  return result;
 }catch{return result;}
}

// Recompute the selected JS assertions from retained Anti JSON, source bytes and
// actual command records. Historical success flags are deliberately not inputs.
export function auditContainerJavaScript(row,commands){
 const errors=[],selected_rea={},source_commands={},assertions={};
 try{
  const bytes=readFileSync(row.selected_script.path);
  if(sha(bytes)!==row.selected_script.sha256)errors.push('selected script digest');
  assertions.anti_selected_task=antiSelected(row.anti,row.expected,bytes);
  for(const kind of ['clean','protected','handoff']){
   const ref=row[kind],matches=commands.filter(c=>c.id===ref?.command_id);
   const command=matches.length===1?matches[0]:null;
   const bound=command&&ref.exit_code===command.exit_code&&ref.timed_out===command.timed_out&&['stdout','stderr'].every(k=>samePath(ref[k]?.path,command[k]?.path)&&ref[k]?.sha256===command[k]?.sha256&&ref[k]?.bytes===command[k]?.bytes);
   if(!bound){errors.push(kind+' command reference');selected_rea[kind]={provenance_ok:false,selected_assertion:false};continue;}
   const sourcePath=join(command.args[2],'index.mjs');
   selected_rea[kind]=reaSelected(command,row.expected,sourcePath);
   source_commands[kind]={command_id:command.id,exit_code:command.exit_code,source_path:sourcePath,source_sha256:sha(readFileSync(sourcePath)),stdout_sha256:command.stdout.sha256};
   if(!selected_rea[kind].provenance_ok)errors.push(kind+' command/source provenance');
   if(kind==='protected'&&!samePath(sourcePath,row.selected_script.path))errors.push('protected selected source path');
   if(kind==='handoff'&&(row.normalization?.originalSha256!==sha(bytes)||row.normalization?.derivativeSha256!==source_commands[kind].source_sha256||sha(Buffer.from(row.normalization?.source??''))!==source_commands[kind].source_sha256))errors.push('normalization source provenance');
  }
  if(!assertions.anti_selected_task)errors.push('Anti selected call');
  if(!selected_rea.clean?.selected_assertion||selected_rea.protected?.selected_assertion||!selected_rea.handoff?.selected_assertion)errors.push('REA selected call handoff');
 }catch(e){errors.push('missing/malformed retained evidence: '+e.message);}
 return {assertions,selected_rea,source_commands,errors,normal_control:'HISTORICAL_RAW_ANTI_JSON_NOT_RETAINED; stored normal flag is not revalidated'};
}

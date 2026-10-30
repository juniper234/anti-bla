import test from 'node:test';
import assert from 'node:assert/strict';
import { inspectJavaScript, normalizeJavaScript } from '../dist/javascript.js';

const inspect=(source,options={})=>inspectJavaScript(Buffer.from(source),{entryExport:'f',...options});
const returnValues=report=>report.facts.filter(f=>f.kind==='return').map(f=>f.value);

test('R2 with and direct eval refuse binding-dependent facts and derivative substitution',()=>{
  const controls=[
    'const x="outer";exports.f=function(o){with(o){return x}}',
    'const x="outer";exports.f=function(){eval("var x=\\"inner\\"");return x}',
    'const x="outer";const y=x;exports.f=function(){eval("var y=\\"inner\\"");return y+"!"}',
    'function x(){};exports.f=function(o){with(o){return typeof x}}',
    'function x(){};exports.f=function(){eval("var x=1");return typeof x}',
    'const x="outer";exports.f=function(o){with(o){if(x==="outer")return "old";return "new"}}',
  ];
  for(const source of controls)for(const assumeStandardIntrinsics of [false,true]){
    const report=inspect(source,{assumeStandardIntrinsics});
    assert.equal(report.status,'UNKNOWN');
    assert.deepEqual(report.facts,[]);
    assert.ok(report.unknowns.some(f=>f.reason==='dynamic-scope'||f.reason==='dynamic-evaluation'));
    const view=normalizeJavaScript(Buffer.from(source),{entryExport:'f',assumeStandardIntrinsics});
    assert.equal(view.source,null);
    assert.deepEqual(view.changes,[]);
  }
});
test('R2 ordinary lexical lookup still yields its proven constant without dynamic scope',()=>{
  assert.deepEqual(returnValues(inspect('const x="outer";exports.f=function(){return x}')),['outer']);
  assert.deepEqual(returnValues(inspect('function x(){};exports.f=function(){return typeof x}')),['function']);
});

test('R3 known if values retain evaluated call and getter findings',()=>{
  const call='export function f(effect){if((effect()&0)===0)return "yes";return "no"}';
  const report=inspect(call);
  assert.ok(report.facts.some(f=>f.kind==='predicate'&&f.value===true));
  assert.ok(report.effects.some(f=>f.reason==='unresolved-call-may-have-effects'&&call.slice(f.range.utf16Start,f.range.utf16End)==='effect()'));
  assert.equal(normalizeJavaScript(Buffer.from(call),{entryExport:'f'}).source,call);
  const getter='export function f(o){if((o.x&0)===0)return "yes";return "no"}';
  const getterReport=inspect(getter);
  assert.ok(getterReport.unknowns.some(f=>f.reason==='reflection-or-accessor'&&getter.slice(f.range.utf16Start,f.range.utf16End)==='o.x'));
  assert.equal(normalizeJavaScript(Buffer.from(getter),{entryExport:'f'}).source,getter);
});
test('R3 only the unselected if branch is pruned, never its evaluated test',()=>{
  const source='export function f(effect,discarded){if((effect()&0)===1){discarded();return "DECOY"}else{return "LIVE"}}';
  const report=inspect(source);
  assert.deepEqual(returnValues(report),['LIVE']);
  assert.deepEqual(report.effects.filter(x=>x.reason==='unresolved-call-may-have-effects').map(x=>source.slice(x.range.utf16Start,x.range.utf16End)),['effect()']);
});

test('R4 local arrow and function initializers are excluded from the requested function root',()=>{
  for(const source of [
    'export function f(){const unused=()=>"DECOY";return "LIVE"}',
    'export function f(){const unused=function(){return "DECOY"};return "LIVE"}',
    'export const f=()=>{const unused=()=>"DECOY";return "LIVE"}',
    'export function f(){const unused=()=>{const deep=()=>"DEEP";return "DECOY"};return "LIVE"}',
  ]){
    const report=inspect(source);
    assert.equal(report.status,'OK');
    assert.deepEqual(returnValues(report),['LIVE']);
    assert.ok(!JSON.stringify(report).includes('DECOY'));
  }
});
test('R4 selected exported arrow and function initializers are unwrapped once',()=>{
  for(const source of ['export const f=()=>"LIVE"','export const f=function(){return "LIVE"}','const f=()=>"LIVE";export {f}']){
    assert.deepEqual(returnValues(inspect(source)),['LIVE']);
  }
});

test('R5 mutable or reassigned export bindings never attribute obsolete initializer returns',()=>{
  const controls=[
    ['let f=()=>"old";f=()=>"new";export {f}','f'],
    ['export let f=()=>"old";f=()=>"new"','f'],
    ['export var f=()=>"old";f=()=>"new"','f'],
    ['export let f=()=>"old"','f'],
    ['export function f(){return "old"};f=()=>"new"','f'],
    ['let f=()=>"old";f=()=>"new";export default f','default'],
    ['let f=()=>"old";f=()=>"new";exports.f=f','f'],
    ['exports.f=()=>"old";exports.f=()=>"new"','f'],
  ];
  for(const [source,entryExport]of controls){
    const report=inspect(source,{entryExport});
    assert.equal(report.status,'UNKNOWN');
    assert.deepEqual(returnValues(report),[]);
    assert.ok(report.unknowns.some(x=>x.reason==='unresolved-export-binding'||x.reason==='multiple-export-definitions'));
    assert.equal(normalizeJavaScript(Buffer.from(source),{entryExport}).source,null);
  }
});
test('R5 immutable named aliases and direct function exports keep their valid root attribution',()=>{
  for(const source of ['const impl=()=>"LIVE";export {impl as f}','export const f=()=>"LIVE"','export function f(){return "LIVE"}']){
    const report=inspect(source);assert.equal(report.status,'OK');assert.deepEqual(returnValues(report),['LIVE']);
  }
});

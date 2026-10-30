import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { inspectJavaScript } from '../dist/javascript.js';

const inspect = (source, options = {}) => inspectJavaScript(Buffer.from(source), options);
const returns = result => result.facts.filter(f => f.kind === 'return').map(f => f.value);

test('root selection recovers a split string without echoing unrelated decoy functions', () => {
  const result = inspect('function distraction(){return "DECOY"} export function answer(){return "invoice" + ":ready"}', { entryExport: 'answer' });
  assert.deepEqual(returns(result), ['invoice:ready']);
  assert.equal(result.roots[0].exportName, 'answer');
  assert.ok(!JSON.stringify(result).includes('DECOY'));
});

test('numeric masks prove opposite ternary polarity and odd-square branches without candidate products', () => {
  const source = `const n = (clock() & 0x7fffc) | 1;
  export function answer(){return
    ((Math.imul(n|9,(n|9)+1)&1)===1 ? 'bad' : 'live:') +
    ((Math.imul(n^24,n^24)&7)===1 ? 'ready' : 'bad');}`.replace('return\n', 'return ');
  const result = inspect(source, { assumeStandardIntrinsics: true });
  assert.deepEqual(returns(result), ['live:ready']);
  assert.equal(result.stats.candidateProducts, 0);
});

test('default inspection does not presume that Math.imul is unchanged', () => {
  assert.deepEqual(returns(inspect('export function f(x){return (Math.imul(x|1,(x|1)+1)&1)===0 ? "yes":"no"}')), []);
});

test('shadowing and direct or aliased intrinsic writes prevent arithmetic proof', () => {
  for (const source of [
    'export function f(Math,x){return (Math.imul(x|1,(x|1)+1)&1)===0 ? "yes":"no"}',
    'Math.imul=()=>1; export function f(x){return (Math.imul(x|1,(x|1)+1)&1)===0 ? "yes":"no"}',
    'const alias=Math; alias.imul=()=>1; export function f(x){return (Math.imul(x|1,(x|1)+1)&1)===0 ? "yes":"no"}'
  ]) assert.deepEqual(returns(inspect(source, { assumeStandardIntrinsics: true })), []);
});

test('getter aliases, eval and reflection remain unknown and never execute', () => {
  const source = 'const obj={get secret(){globalThis.__antiBlaExecuted=true;return "x"}}; const alias=obj; export function f(){eval("globalThis.__antiBlaExecuted=true");return Reflect.get(alias,"secret")}';
  const result = inspect(source, { assumeStandardIntrinsics: true });
  assert.equal(globalThis.__antiBlaExecuted, undefined);
  assert.deepEqual(returns(result), []);
  assert.ok(result.unknowns.some(x => x.reason === 'dynamic-evaluation'));
  assert.ok(result.unknowns.some(x => x.reason === 'reflection-or-accessor'));
});

test('UTF-8 byte provenance matches original even before astral Unicode', () => {
  const source = '// 🌿 中文\nexport function f(){return "orchid"+":ok"}';
  const bytes = Buffer.from(source);
  const result = inspectJavaScript(bytes);
  const fact = result.facts.find(x => x.kind === 'return');
  assert.equal(fact.value, 'orchid:ok');
  assert.equal(bytes.subarray(fact.range.byteStart, fact.range.byteEnd).toString(), '"orchid"+":ok"');
  assert.equal(result.source.sha256, createHash('sha256').update(bytes).digest('hex'));
  assert.equal(bytes.toString(), source);
});

test('benign unknown branches are not guessed or expanded combinatorially', () => {
  const result = inspect('export function f(x){return (x ? "a":"b")+(x ? "c":"d")}');
  assert.deepEqual(returns(result), []);
  assert.ok(result.unknowns.some(x => x.reason === 'unresolved-return'));
});

test('syntax, source size, deep AST and excessive facts fail closed', () => {
  for (const source of ['export function {', ' '.repeat(8*1024*1024+1), 'export function f(){return '+ '!'.repeat(3000)+'true}', Array.from({length:257},(_,i)=>`export function f${i}(){return ${i}}`).join('\n')]) {
    const result = inspect(source);
    assert.equal(result.status, 'UNKNOWN');
    assert.ok(result.unknowns.length > 0);
  }
});

test('TypeScript and JSX loader selection preserves bounded primitive recovery', () => {
  assert.deepEqual(returns(inspect('export function f(x: number): string { return "typed:" + "ok" }', { loader: 'ts' })), ['typed:ok']);
  assert.equal(inspect('export const view=<div/>', { loader: 'jsx' }).status, 'OK');
});

test('missing requested export reports unknown rather than summarizing decoys', () => {
  const result = inspect('function decoy(){return "wrong"}', { entryExport: 'missing' });
  assert.equal(result.status, 'UNKNOWN');
  assert.deepEqual(returns(result), []);
  assert.ok(result.unknowns.some(x => x.reason === 'entry-export-not-found'));
});

test('benign intrinsic constructors do not disable independent numeric proof', () => {
  const result = inspect('const values=new Array(3); const n=(clock()&12)|1; export function f(){return (Math.imul(n^4,n^4)&7)===1?"ok":"bad"}', {assumeStandardIntrinsics:true});
  assert.deepEqual(returns(result), ['ok']);
});

test('global-object access to intrinsic namespace invalidates its assumptions', () => {
  const result=inspect('globalThis.Math.imul=()=>1;const n=(clock()&12)|1;export function f(){return (Math.imul(n,n)&7)===1?"yes":"no"}',{assumeStandardIntrinsics:true});
  assert.deepEqual(returns(result),[]);
});

test('bounded intrinsic character encoding recovers strings only with explicit assumptions', () => {
  const source='export function f(){return String.fromCharCode(111,114,99,104,105,100)+String.fromCodePoint(0x1f33f)}';
  assert.deepEqual(returns(inspect(source,{assumeStandardIntrinsics:true})),['orchid🌿']);
  assert.deepEqual(returns(inspect(source)),[]);
  assert.deepEqual(returns(inspect('export function f(String){return String.fromCharCode(65)}',{assumeStandardIntrinsics:true})),[]);
  assert.deepEqual(returns(inspect('export function f(){return String.fromCodePoint(-1)}',{assumeStandardIntrinsics:true})),[]);
});

test('CommonJS properties and ESM default references resolve their lexical function roots', () => {
  assert.deepEqual(returns(inspect('const f=()=>"live:"+"cjs";exports.answer=f',{entryExport:'answer'})),['live:cjs']);
  assert.deepEqual(returns(inspect('function f(){return "live:"+"module"}module.exports.answer=f',{entryExport:'answer'})),['live:module']);
  assert.deepEqual(returns(inspect('function f(){return "live:"+"esm"}export default f',{entryExport:'default'})),['live:esm']);
  assert.equal(inspect('const exports={};exports.answer=()=>"fake"',{entryExport:'answer'}).status,'UNKNOWN');
});

test('oversized root names and primitive values cannot amplify the bounded summary', () => {
  const longName='n'.repeat(10000);
  const named=inspect(`export function ${longName}(){return 'x'}`);
  assert.equal(named.status,'UNKNOWN');
  assert.ok(JSON.stringify(named).length<10000);
  const longValue=inspect('export function f(){return '+JSON.stringify('x'.repeat(65537))+'}');
  assert.equal(longValue.status,'UNKNOWN');
  assert.ok(longValue.unknowns.some(x=>x.reason==='primitive-string-limit'));
});

test('benign complex graph with 512 legitimate alternatives stays unknown without cross products', () => {
  const helpers=Array.from({length:256},(_,i)=>`function helper${i}(x){const n=x|0;return ((n^3)&7)+(n*2)}`).join('\n');
  const choices=Array.from({length:9},(_,i)=>`((flags&${2**i})?${JSON.stringify(String.fromCharCode(97+i))}:${JSON.stringify(String.fromCharCode(65+i))})`).join('+');
  const result=inspect(helpers+`\nexport function choose(flags){return ${choices}}`,{entryExport:'choose',assumeStandardIntrinsics:true});
  assert.equal(result.status,'OK');
  assert.deepEqual(returns(result),[]);
  assert.equal(result.stats.candidateProducts,0);
  assert.ok(result.stats.astNodes>5000);
  assert.ok(result.unknowns.some(x=>x.reason==='unresolved-return'));
});

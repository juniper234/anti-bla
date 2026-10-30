import test from 'node:test';
import assert from 'node:assert/strict';
import { inspectJavaScript, normalizeJavaScript } from '../dist/javascript.js';

test('inspection derivative folds proven string while retaining independent heap effects and original bytes', () => {
  const original=Buffer.from('const n=(clock()&12)|1;export function f(){stepHeap();return ((Math.imul(n|7,(n|7)+1)&1)===1?"bad":"/api/")+((Math.imul(n^4,n^4)&7)===1?"ready":"bad")}');
  const before=Buffer.from(original);
  const result=normalizeJavaScript(original,{assumeStandardIntrinsics:true});
  assert.ok(result.changes.length>0);
  assert.match(result.source,/stepHeap\(\)/);
  assert.match(result.source,/return "\/api\/ready"/);
  assert.equal(result.scope,'inspection-only');
  assert.equal(result.fullEquivalence,'UNKNOWN');
  assert.deepEqual(original,before);
  assert.equal(inspectJavaScript(Buffer.from(result.source)).facts.find(x=>x.kind==='return').value,'/api/ready');
});
test('known-result masks with a getter or unresolved call retain its potential effects', () => {
  const original='export function f(){return ((obj.x & 0)===0?"yes":"no")}';
  const result=normalizeJavaScript(Buffer.from(original),{assumeStandardIntrinsics:true});
  assert.equal(result.source,original);
  assert.deepEqual(result.changes,[]);
});

test('refused normalization never emits an empty substitute artifact', () => {
  const result=normalizeJavaScript(Buffer.from('export function {'));
  assert.equal(result.analysis.status,'UNKNOWN');
  assert.equal(result.source,null);
  assert.equal(result.derivativeSha256,null);
  assert.deepEqual(result.changes,[]);
});

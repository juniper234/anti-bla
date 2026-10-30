import test from 'node:test';
import assert from 'node:assert/strict';
import { inspectJavaScript, normalizeJavaScript } from '../dist/javascript.js';

// Independent minimal corpus and literal algorithm fixture; no upstream tests or challenge artifacts.
// The expected digest 2422806856 was independently calculated with unsigned BigInt multiplication.
const helper = `const entries=[{coupledAnchorSymbol:'',triggerPayload:''}];
function checksum(seedInput=0){
 if(!Array.isArray(entries)||entries.length<1)return 0;
 let acc=((seedInput|0)^0x26b5c67b)>>>0;
 for(let i=0;i<entries.length;i++){
  const entry=entries[i];
  if(!entry||typeof entry.coupledAnchorSymbol!=="string"||typeof entry.triggerPayload!=="string")return 0;
  const text=entry.coupledAnchorSymbol+"::"+entry.triggerPayload;
  for(let j=0;j<text.length;j++){
   acc=Math.imul(acc^text.charCodeAt(j),0x85ebca6b)>>>0;
   acc=((acc<<13)|(acc>>>19))>>>0;
  }
 }
 return acc>>>0;
}`;
const fixture = (expect = 0) => `${helper}
const seed=(clock()&0x7fffc)|((typeof checksum==='function'&&checksum(0)===${expect})?1:0);
export function answer(){return (Math.imul(seed^20,seed^20)&7)===1?'accepted':'changed'}`;
const run = source => inspectJavaScript(Buffer.from(source), {assumeStandardIntrinsics:true,entryExport:'answer'});
const output = report => report.facts.filter(x=>x.kind==='return').map(x=>x.value);

test('structurally validated digest computes actual corpus and establishes seed bits', () => {
  const report = run(fixture(2422806856));
  assert.deepEqual(output(report), ['accepted']);
  assert.equal(report.digestProofs[0].digest, 2422806856);
  assert.equal(report.digestProofs[0].entries, 1);
});
test('corpus or expected-value tampering selects changed path instead of assuming marker parity', () => {
  assert.deepEqual(output(run(fixture(1))), ['changed']);
  assert.deepEqual(output(run(fixture(2422806856).replace("triggerPayload:''", "triggerPayload:'different'"))), ['changed']);
});
test('helper mutation, corpus escape, property mutation and getter corpus invalidate digest proof', () => {
  for(const source of [
    fixture(2422806856).replace('0x85ebca6b','0x85ebca6d'),
    fixture(2422806856).replace('const seed=', 'leak(entries);const seed='),
    fixture(2422806856).replace('const seed=', 'entries[0].triggerPayload="changed";const seed='),
    fixture(2422806856).replace("triggerPayload:''", "get triggerPayload(){return ''}"),
    fixture(2422806856).replace('function checksum(seedInput=0)', 'function checksum(seedInput=1)')
  ]) { const report=run(source); assert.equal(report.digestProofs.length,0); assert.deepEqual(output(report),[]); }
});
test('proof resolves renamed lexical bindings and rejects a shadowed array intrinsic', () => {
  const renamed = fixture(2422806856).replaceAll('entries','flowers').replaceAll('checksum','measure').replaceAll('seedInput','initial');
  assert.deepEqual(output(run(renamed)), ['accepted']);
  assert.equal(run('const Array={isArray:()=>true};'+renamed).digestProofs.length,0);
});

test('R1 corpus binding tags cannot collide with global spellings or substituted outer bindings', () => {
  const original=fixture(2422806856);
  const changed=(name)=>original.replaceAll('entries.length',name+'.length').replace('entries[i]',name+'[i]');
  const controls=[
    'globalThis.$corpus=[{coupledAnchorSymbol:"other",triggerPayload:"data"}];'+changed('$corpus'),
    changed('unboundCorpus'),
    'const outerCorpus=[{coupledAnchorSymbol:"other",triggerPayload:"data"}];'+changed('outerCorpus'),
    original.replace('entries[i]','seedInput[i]'),
    ...['entries.length<1','i<entries.length','entries[i]'].map(part=>original.replace(part,part.replace('entries','$corpus'))),
  ];
  for(const source of controls){
    const report=run(source);
    assert.equal(report.digestProofs.length,0,'unsupported corpus substitution must invalidate the exact helper proof');
    assert.deepEqual(output(report),[]);
    const view=normalizeJavaScript(Buffer.from(source),{assumeStandardIntrinsics:true,entryExport:'answer'});
    assert.deepEqual(view.changes,[]);
  }
});
test('R1 alpha-renamed corpus bindings retain their distinct structural identity', () => {
  for(const name of ['$corpus','CorpusBinding','flowers']){
    const source=fixture(2422806856).replaceAll('entries',name).replaceAll('checksum','measure');
    const report=run(source);
    assert.equal(report.digestProofs.length,1);
    assert.deepEqual(output(report),['accepted']);
  }
});

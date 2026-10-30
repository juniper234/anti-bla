import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { mkdtempSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
const api = await import('../dist/formats/index.js').catch(e => e.code === 'ERR_MODULE_NOT_FOUND' ? {} : Promise.reject(e));
const dataTemp=mkdtempSync(join(tmpdir(),'anti-bla-data-tests-'));
const wasm = Buffer.from('0061736d010000000105016000017f03020100070a0106616e7377657200000a06010400412a0b', 'hex');
const hash = b => createHash('sha256').update(b).digest('hex');
export function safeFixture(extra = {}) {
  const h = Buffer.from(JSON.stringify({ weight: { dtype:'F32', shape:[4], data_offsets:[0,16], ...extra } }));
  const p = Buffer.alloc(8); p.writeBigUInt64LE(BigInt(h.length));
  return Buffer.concat([p,h,Buffer.from('0000a03f000000c0000000000000f040','hex')]);
}
export function ggufFixture() {
  const b = Buffer.alloc(96); b.write('GGUF'); b.writeUInt32LE(3,4); b.writeBigUInt64LE(1n,8);
  b.writeBigUInt64LE(6n,24); b.write('weight',32); b.writeUInt32LE(1,38); b.writeBigUInt64LE(4n,42);
  b.writeUInt32LE(0,50); b.writeBigUInt64LE(0n,54); Buffer.from('0000a03f000000c0000000000000f040','hex').copy(b,64);
  // Descriptor ends at 62, payload starts at 64, exact tensor ends at 80.
  return b.subarray(0,80);
}
export function sqliteFixture() {
  const dir = mkdtempSync(join(dataTemp,'anti-bla-data-test-')); const path = join(dir,'fixture.sqlite');
  const db = new DatabaseSync(path);
  db.function('missing_unseal',{deterministic:true},v=>String(v));
  db.exec(`CREATE TABLE business (id INTEGER PRIMARY KEY, name TEXT, amount REAL, payload BLOB);
    INSERT INTO business VALUES (7,'orchid',12.5,x'00ff');
    CREATE TABLE honey (stored TEXT, trap TEXT GENERATED ALWAYS AS (missing_unseal(stored)) VIRTUAL);
    INSERT INTO honey(stored) VALUES ('untrusted metadata');`);
  db.close(); return readFileSync(path);
}
test('WASM recovers the actual export body/type, with original indexed bytes intact',()=>{
  assert.equal(typeof api.inspectWasm,'function','bounded WASM recovery is missing');
  const b=Buffer.from(wasm), before=hash(b), r=api.inspectWasm(b,{exportName:'answer'});
  assert.equal(r.status,'ok'); assert.equal(r.selected.functionIndex,0);
  assert.deepEqual(r.selected.type,{params:[],results:['i32']});
  assert.equal(r.selected.body.base64,'AEEqCw=='); assert.equal(r.selected.aliasCount,1);
  assert.equal(r.source.sha256,before); assert.equal(hash(b),before); assert.equal(r.equivalence,'UNKNOWN');
});
test('WASM malformed duplicate sections, truncation, LEB overflow and bad export indices fail closed',()=>{
  assert.equal(typeof api.inspectWasm,'function');
  for(const b of [wasm.subarray(0,-1),Buffer.concat([wasm,Buffer.from('010101','hex')]),
    Buffer.from('0061736d0100000001ffffffff1f','hex'),
    Buffer.from(wasm.toString('hex').replace('616e737765720000','616e737765720009'),'hex')])
    assert.notEqual(api.inspectWasm(b).status,'ok');
});
test('SQLite recovers stored business values despite unavailable honey virtual-column UDF',()=>{
  assert.equal(typeof api.inspectSqlite,'function','bounded SQLite recovery is missing');
  const b=sqliteFixture(), before=hash(b), r=api.inspectSqlite(b,{table:'business'});
  assert.equal(r.status,'ok'); assert.equal(r.rows[0].rowid,7);
  assert.deepEqual(r.rows[0].values.map(v=>Object.hasOwn(v,'value')?v.value:v.base64),[null,'orchid',12.5,'AP8=']);
  assert.equal(hash(b),before); assert.equal(r.source.sha256,before); assert.equal(r.schema.count,2);
  const honey=api.inspectSqlite(b,{table:'honey'}); assert.equal(honey.status,'ok');
  assert.equal(honey.rows[0].values.length,1); assert.equal(honey.rows[0].values[0].value,'untrusted metadata');
});
test('SQLite schema views never block the unrelated ordinary table',()=>{
  const dir=mkdtempSync(join(dataTemp,'anti-bla-data-view-')),path=join(dir,'view.sqlite');
  const db=new DatabaseSync(path);db.exec("CREATE TABLE data(x TEXT); INSERT INTO data VALUES ('actual'); CREATE VIEW bait AS SELECT x FROM data;");db.close();
  const r=api.inspectSqlite(readFileSync(path),{table:'data'});assert.equal(r.status,'ok');assert.equal(r.rows[0].values[0].value,'actual');
});
test('SQLite refuses WAL identity, impossible page count and truncated pages',()=>{
  assert.equal(typeof api.inspectSqlite,'function'); const b=sqliteFixture();
  const wal=Buffer.from(b); wal[18]=2; const bad=Buffer.from(b); bad.writeUInt32BE(0xffffffff,28);
  for(const x of [wal,bad,b.subarray(0,b.length-1)]) assert.notEqual(api.inspectSqlite(x,{table:'business'}).status,'ok');
});
test('Safetensors recovers literal real values while indexing deep untrusted extra fields',()=>{
  assert.equal(typeof api.inspectModel,'function','bounded model recovery is missing');
  let deep={notice:'not authority'}; for(let i=0;i<40;i++) deep={next:deep};
  const b=safeFixture({deep}), r=api.inspectModel(b,{tensor:'weight'});
  assert.equal(r.status,'ok'); assert.equal(r.format,'safetensors');
  assert.deepEqual(r.selected.shape,[4]); assert.deepEqual(r.selected.values,[1.25,-2,0,7.5]);
  assert.equal(r.selected.data.base64,'AACgPwAAAMAAAAAAAADwQA=='); assert.equal(r.equivalence,'UNKNOWN');
  assert.ok(r.selected.extras.length); assert.equal(r.source.sha256,hash(b));
});
test('GGUF recovers F32 tensor with exact aligned data source ranges',()=>{
  assert.equal(typeof api.inspectModel,'function'); const r=api.inspectModel(ggufFixture(),{tensor:'weight'});
  assert.equal(r.status,'ok'); assert.equal(r.selected.data.offset,64);
  assert.deepEqual(r.selected.values,[1.25,-2,0,7.5]); assert.deepEqual(r.selected.shape,[4]);
});
test('Models reject duplicate keys, size mismatch, overlap, unknown dtype and over-limit depth',()=>{
  assert.equal(typeof api.inspectModel,'function');
  const h=Buffer.from('{"weight":{"dtype":"F32","dtype":"F32","shape":[4],"data_offsets":[0,16]}}');
  const p=Buffer.alloc(8);p.writeBigUInt64LE(BigInt(h.length));
  let deep={};for(let i=0;i<140;i++)deep={next:deep};
  for(const b of [safeFixture({shape:[5]}),safeFixture({dtype:'NEW'}),safeFixture({deep}),
    Buffer.concat([p,h,Buffer.alloc(16)]),ggufFixture().subarray(0,70)]) assert.notEqual(api.inspectModel(b).status,'ok');
});
test('All adapters validate bounded options and cap every preview without treating names as proof',()=>{
  assert.equal(typeof api.inspectWasm,'function');assert.equal(typeof api.inspectModel,'function');assert.equal(typeof api.inspectSqlite,'function');
  for(const [f,b,k] of [[api.inspectWasm,wasm,'exportName'],[api.inspectModel,safeFixture(),'tensor'],[api.inspectSqlite,sqliteFixture(),'table']]) {
    for(const o of [{offset:-1},{offset:NaN},{limit:0},{limit:100000},{[k]:'a'.repeat(4097)}]) assert.notEqual(f(b,o).status,'ok');
    assert.equal(f(b,{limit:1}).equivalence,'UNKNOWN');
  }
});
test('SQLite overflow values retain exact original source segments and detect overflow cycles',()=>{
  const dir=mkdtempSync(join(dataTemp,'anti-bla-data-overflow-')),path=join(dir,'big.sqlite');
  const db=new DatabaseSync(path);db.exec('PRAGMA page_size=512; CREATE TABLE big(x BLOB)');db.prepare('INSERT INTO big VALUES (?)').run(Buffer.alloc(2000,0x5a));db.close();
  const b=readFileSync(path),r=api.inspectSqlite(b,{table:'big'});assert.equal(r.status,'ok');
  const v=r.rows[0].values[0];assert.equal(v.byteLength,2000);assert.ok(Array.isArray(v.sourceRanges),'missing original overflow source segments');assert.ok(v.sourceRanges.length>1);
  const exact=Buffer.concat(v.sourceRanges.map(x=>b.subarray(x.offset,x.offset+x.length)));assert.equal(exact.length,2000);assert.deepEqual(exact,Buffer.alloc(2000,0x5a));
  const corrupt=Buffer.from(b),overflowStart=v.sourceRanges[1].offset-4;
  corrupt.writeUInt32BE(Math.floor(overflowStart/512)+1,overflowStart);
  assert.equal(api.inspectSqlite(corrupt,{table:'big'}).status,'error');
});
test('WASM requested export wins over equally real huge alias names while previews remain bounded',()=>{
  const leb=n=>{const a=[];do{let x=n&127;n=Math.floor(n/128);if(n)x|=128;a.push(x);}while(n);return Buffer.from(a);};
  const long=Buffer.from('documentation_alias_'+'e'.repeat(12000));
  const payload=Buffer.concat([Buffer.from('0206616e737765720000','hex'),leb(long.length),long,Buffer.from([0,0])]);
  const b=Buffer.concat([wasm.subarray(0,19),Buffer.from([7]),leb(payload.length),payload,wasm.subarray(31)]);
  const r=api.inspectWasm(b,{exportName:'answer'});assert.equal(r.status,'ok');assert.equal(r.selected.aliasCount,2);assert.equal(r.selected.body.base64,'AEEqCw==');
  const list=api.inspectWasm(b);assert.equal(list.status,'ok');assert.equal(list.exports.entries[1].name.byteLength,12020);assert.equal(Buffer.byteLength(list.exports.entries[1].name.preview),128);assert.equal(list.exports.entries[1].name.sha256,hash(long));
});
test('Safetensors overlaps are refused and GGUF metadata arrays remain bounded independent of name authority',()=>{
  const h=Buffer.from('{"a":{"dtype":"U8","shape":[2],"data_offsets":[0,2]},"b":{"dtype":"U8","shape":[2],"data_offsets":[1,3]}}');const p=Buffer.alloc(8);p.writeBigUInt64LE(BigInt(h.length));
  assert.equal(api.inspectModel(Buffer.concat([p,h,Buffer.alloc(3)])).status,'error');
  const b=ggufFixture(),x=Buffer.from(b);x.writeBigUInt64LE(100001n,16);assert.equal(api.inspectModel(x).status,'unknown');
});
test('Malformed shifted GGUF indexes a unique tail-fit sidecar candidate under explicit assumptions, never a valid model',()=>{
  const original=ggufFixture(),kv=Buffer.alloc(28);kv.writeBigUInt64LE(3n);kv.write('doc',8);kv.writeUInt32LE(8,11);kv.writeBigUInt64LE(5n,15);kv.write('notes',23);
  const b=Buffer.concat([original.subarray(0,24),kv,original.subarray(24)]);b.writeBigUInt64LE(1n,16);
  const r=api.inspectModel(b,{tensor:'weight'});assert.equal(r.status,'unknown','malformed standard layout needs explicit conditional candidate');
  assert.equal(r.equivalence,'UNKNOWN');assert.equal(r.recoveryCandidate.selected.data.offset,92);
  assert.deepEqual(r.recoveryCandidate.selected.values,[1.25,-2,0,7.5]);
  assert.ok(r.recoveryCandidate.assumptions.includes('No trailing bytes beyond the declared tensor extents.'));
  assert.equal(r.selected,undefined);assert.equal(r.source.sha256,hash(b));
});
test('SQLite schema overflow previews truncate at a valid UTF-8 boundary and retain source provenance',()=>{
  const dir=mkdtempSync(join(dataTemp,'anti-bla-data-unicode-')),path=join(dir,'unicode.sqlite'),db=new DatabaseSync(path);
  db.exec('PRAGMA page_size=512; CREATE TABLE unicode_data(x TEXT /*'+ '中'.repeat(2000) +'*/); INSERT INTO unicode_data VALUES (\'ordinary\')');db.close();
  const b=readFileSync(path),r=api.inspectSqlite(b,{table:'unicode_data'});assert.equal(r.status,'ok');assert.equal(r.rows[0].values[0].value,'ordinary');
  assert.ok(Buffer.byteLength(r.selected.sql.preview)<=128);assert.ok(Array.isArray(r.selected.sql.sourceRanges),'schema overflow source ranges are missing');assert.ok(r.selected.sql.sourceRanges.length>1);
});
test('SQLite selected responses refuse a scalar-field flood instead of expanding every stored cell',()=>{
  const dir=mkdtempSync(join(dataTemp,'anti-bla-data-wide-')),path=join(dir,'wide.sqlite'),db=new DatabaseSync(path);
  db.exec('CREATE TABLE wide('+Array.from({length:20},(_,i)=>'c'+i+' INTEGER').join(',')+')');
  const insert=db.prepare('INSERT INTO wide VALUES ('+Array(20).fill('?').join(',')+')');for(let i=0;i<20;i++)insert.run(...Array(20).fill(7));db.close();
  const b=readFileSync(path);assert.equal(api.inspectSqlite(b,{table:'wide'}).status,'unknown');assert.equal(api.inspectSqlite(b,{table:'wide',limit:1}).status,'ok');
});
test('WASM caps aggregate type expansion even when each individual vector fits',()=>{
  const leb=n=>{const a=[];do{let x=n&127;n=Math.floor(n/128);if(n)x|=128;a.push(x);}while(n);return Buffer.from(a);};
  const type=Buffer.concat([Buffer.from([0x60]),leb(1000),Buffer.alloc(1000,0x7f),Buffer.from([0])]);
  const payload=Buffer.concat([leb(501),...Array(501).fill(type)]),b=Buffer.concat([wasm.subarray(0,8),Buffer.from([1]),leb(payload.length),payload]);
  assert.equal(api.inspectWasm(b).status,'unknown');
});

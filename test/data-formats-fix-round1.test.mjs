import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync,readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { DatabaseSync } from 'node:sqlite';
import { inspectModel,inspectSqlite,inspectWasm } from '../dist/formats/index.js';
const dir=mkdtempSync(join(tmpdir(),'anti-bla-data-fix-tests-'));
const wasm=Buffer.from('0061736d010000000105016000017f03020100070a0106616e7377657200000a06010400412a0b','hex');
function gguf(){const b=Buffer.alloc(80);b.write('GGUF');b.writeUInt32LE(3,4);b.writeBigUInt64LE(1n,8);b.writeBigUInt64LE(6n,24);b.write('weight',32);b.writeUInt32LE(1,38);b.writeBigUInt64LE(4n,42);Buffer.from('0000a03f000000c0000000000000f040','hex').copy(b,64);return b;}
test('I1 GGUF requires exact magic bytes, rejecting high-bit ASCII lookalikes without changing the genuine tensor',()=>{
  const b=gguf(),bad=Buffer.from(b);Buffer.from('c7c7d5c6','hex').copy(bad);
  assert.equal(inspectModel(b,{tensor:'weight'}).status,'ok');
  assert.equal(inspectModel(bad,{tensor:'weight'}).status,'error','high-bit bytes must not enter GGUF parser');
  assert.deepEqual(inspectModel(b,{tensor:'weight'}).selected.values,[1.25,-2,0,7.5]);
});
function sqliteOwn(mode='pair'){
  const path=join(mkdtempSync(join(dir,'sqlite-')),'owned.sqlite'),db=new DatabaseSync(path);db.exec('PRAGMA page_size=512; CREATE TABLE target(v TEXT)');
  const insert=db.prepare('INSERT INTO target(rowid,v) VALUES (?,?)');
  if(mode==='holes'){for(let n=1;n<=5;n++)insert.run(n,'x'.repeat(40));db.exec('DELETE FROM target WHERE rowid IN(2,4)');}
  else if(mode==='signed'){for(const n of [-9223372036854775808n,-9n,-1n,0n,1n,9007199254740993n,9223372036854775807n])insert.run(n,'stored');}
  else if(mode==='interior'){for(let n=1;n<=100;n++)insert.run(n,'x'.repeat(60));}
  else{insert.run(1,'first');insert.run(2,'second');}
  db.close();return readFileSync(path);
}
test('I2 SQLite validates visited freeblock chains, minimum/extents and disjointness from live/header bytes',()=>{
  const b=sqliteOwn('holes'),base=512,head=b.readUInt16BE(base+1),next=b.readUInt16BE(base+head);
  assert.equal(b[base],13);assert.ok(head>0&&next>head,'trusted fixture needs two genuine ordered freeblocks');
  const normal=inspectSqlite(b,{table:'target'});assert.equal(normal.status,'ok');assert.deepEqual(normal.rows.map(r=>r.rowid),[1,3,5]);
  const cases=[['cycle',x=>x.writeUInt16BE(head,base+head)],['backward',x=>x.writeUInt16BE(head-4,base+head)],
    ['size<4',x=>x.writeUInt16BE(3,base+head+2)],['outside usable page',x=>x.writeUInt16BE(513-head,base+head+2)],
    ['overlap next freeblock',x=>x.writeUInt16BE(next-head+1,base+head+2)],['header/pointers',x=>x.writeUInt16BE(8,base+1)],
    ['live cell',x=>x.writeUInt16BE(x.readUInt16BE(base+8),base+1)],['visited sqlite_schema header',x=>x.writeUInt16BE(100,101)]];
  for(const [label,mutate]of cases){const x=Buffer.from(b);mutate(x);assert.equal(inspectSqlite(x,{table:'target'}).status,'error',label);}
});
test('I2 SQLite preserves signed64-bit rowid controls without claiming unvisited database integrity',()=>{
  const r=inspectSqlite(sqliteOwn('signed'),{table:'target'});assert.equal(r.status,'ok');
  assert.deepEqual(r.rows.map(x=>x.rowid),['-9223372036854775808',-9,-1,0,1,'9007199254740993','9223372036854775807']);
  assert.equal(r.validation.fullDatabase,'UNKNOWN');
});
test('I2 SQLite rejects duplicate/descending live rowids and required payload-fraction violations',()=>{
  const b=sqliteOwn(),base=512,first=base+b.readUInt16BE(base+8),second=base+b.readUInt16BE(base+10);
  assert.equal(b[first+1],1);assert.equal(b[second+1],2);assert.equal(inspectSqlite(b,{table:'target'}).status,'ok');
  for(const id of [1,0]){const x=Buffer.from(b);x[second+1]=id;assert.equal(inspectSqlite(x,{table:'target'}).status,'error','duplicate/descending key');}
  for(const at of [21,22,23]){const x=Buffer.from(b);x[at]=0;assert.equal(inspectSqlite(x,{table:'target'}).status,'error','required payload fraction byte '+at);}
});
test('I2 SQLite enforces inherited interior key ranges and pointer-key order across valid multi-page controls',()=>{
  const b=sqliteOwn('interior'),base=512;assert.equal(b[base],5,'trusted fixture must contain an interior root');
  const normal=inspectSqlite(b,{table:'target',limit:1});assert.equal(normal.status,'ok');assert.equal(normal.rowCount,100);assert.equal(normal.rows[0].rowid,1);
  const first=base+b.readUInt16BE(base+12),child=b.readUInt32BE(first),upper=b[first+4];assert.ok(upper<127&&upper>1);
  const leaf=(child-1)*512;assert.equal(b[leaf],13);const count=b.readUInt16BE(leaf+3),last=leaf+b.readUInt16BE(leaf+8+(count-1)*2);assert.ok(b[last]<128);assert.equal(b[last+1],upper);
  const range=Buffer.from(b);range[last+1]=upper+1;assert.equal(inspectSqlite(range,{table:'target',limit:1}).status,'error','leaf key beyond inherited upper bound');
  const order=Buffer.from(b),p0=order.readUInt16BE(base+12),p1=order.readUInt16BE(base+14);order.writeUInt16BE(p1,base+12);order.writeUInt16BE(p0,base+14);
  assert.equal(inspectSqlite(order,{table:'target',limit:1}).status,'error','interior pointer array key order');
});
function wasmSection(id,payload,at=19){return Buffer.concat([wasm.subarray(0,at),Buffer.from([id,payload.length,...payload]),wasm.subarray(at)]);}
test('I3 WASM numeric table elements are rejected for both defined and imported tables',()=>{
  const defined=wasmSection(4,[1,0x7f,0,1]),imported=wasmSection(2,[1,1,109,1,116,1,0x7f,0,1],15);
  assert.deepEqual([defined,imported].map(b=>inspectWasm(b,{exportName:'answer'}).status),['error','error']);
});
test('I3 WASM shared memory without maximum is rejected for definitions and imports',()=>{
  const defined=wasmSection(5,[1,2,1]),imported=wasmSection(2,[1,1,109,1,120,2,2,1],15);
  assert.deepEqual([defined,imported].map(b=>inspectWasm(b,{exportName:'answer'}).status),['error','error']);
});
test('I3 WASM table/memory profiles preserve supported controls and label extensions UNKNOWN',()=>{
  for(const b of [wasmSection(4,[1,0x70,0,1]),wasmSection(4,[1,0x6f,1,1,2]),wasmSection(5,[1,3,1,2]),
    wasmSection(2,[1,1,109,1,116,1,0x70,0,1],15),wasmSection(2,[1,1,109,1,120,2,3,1,2],15)])assert.equal(inspectWasm(b,{exportName:'answer'}).status,'ok');
  const extensions=[wasmSection(4,[1,0x70,2,1]),wasmSection(5,[1,4,1]),wasmSection(4,[1,0x63,0x70,0,1])];
  assert.deepEqual(extensions.map(b=>inspectWasm(b,{exportName:'answer'}).status),['unknown','unknown','unknown']);
  for(const b of [wasmSection(4,[1,0x70,1,2,1]),wasmSection(5,[1,1,2,1])])assert.equal(inspectWasm(b,{exportName:'answer'}).status,'error');
});

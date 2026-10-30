import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

import { inspectAsar as inspect, readAsarEntry as read } from '../dist/asar.js';
const sha = bytes => createHash('sha256').update(bytes).digest('hex');

// Independent Chromium-Pickle fixture writer: no production/upstream helpers.
function archive(header, payload = Buffer.alloc(0)) {
  const json = Buffer.from(typeof header === 'string' ? header : JSON.stringify(header));
  const framed = Buffer.alloc(16 + Math.ceil(json.length / 4) * 4);
  framed.writeUInt32LE(4, 0);
  framed.writeUInt32LE(framed.length - 8, 4);
  framed.writeUInt32LE(framed.length - 12, 8);
  framed.writeUInt32LE(json.length, 12);
  json.copy(framed, 16);
  return Buffer.concat([framed, payload]);
}
const manifest = Buffer.from('{"main":"main.js"}');
const code = Buffer.from('module.exports = 42;\n');
const tiny = () => archive({ files: {
  'package.json': { size: manifest.length, offset: '0' },
  'main.js': { size: code.length, offset: String(manifest.length) },
} }, Buffer.concat([manifest, code]));

test('independent tiny ASAR exposes original package/main bytes and coordinates without rewriting', () => {
  const bytes = tiny(); const before = sha(bytes);
  const facts = inspect(bytes);
  assert.equal(facts?.status, 'ok');
  assert.equal(facts.archive.sha256, before);
  assert.equal(facts.totalEntries, 2);
  assert.deepEqual(facts.entries.map(x => x.path.text), ['package.json', 'main.js']);
  assert.equal(facts.behavioralEquivalence, 'unknown');
  for (const [path, content, offset] of [['package.json', manifest, 0], ['main.js', code, manifest.length]]) {
    const result = read(bytes, { path });
    assert.equal(result?.status, 'ok');
    assert.equal(result.view.archiveOffset, bytes.readUInt32LE(4) + 8 + offset);
    assert.equal(result.view.sha256, sha(content));
    assert.deepEqual(Buffer.from(result.view.base64, 'base64'), content);
    assert.deepEqual(bytes.subarray(result.view.archiveOffset, result.view.archiveOffset + result.view.length), content);
  }
  assert.equal(sha(bytes), before);
});

test('entry views are bounded, addressable and clip only at entry end', () => {
  const bytes = archive({ files: { blob: { offset: '0', size: 6000 } } }, Buffer.alloc(6000, 0x7a));
  assert.equal(read(bytes, { path: 'blob' })?.view?.length, 1024);
  const view = read(bytes, { path: 'blob', offset: 5998, length: 4096 });
  assert.equal(view?.status, 'ok');
  assert.equal(view.view.length, 2);
  assert.equal(view.view.entryOffset, 5998);
  assert.equal(view.view.sha256, '4a60bf7d4bc1e485744cf7e8d0860524752fca1ce42331be7c439fd23043f151');
  assert.equal(read(bytes, { path: 'blob', length: 4097 })?.reason?.code, 'ASAR_INVALID_SELECTOR');
  assert.equal(read(bytes, { path: 'blob', offset: 6001 })?.status, 'error');
  assert.equal(read(bytes, { path: 'absent' })?.reason?.code, 'ASAR_ENTRY_NOT_FOUND');
});

test('UTF-8 names and zero-byte entries are preserved exactly', () => {
  const bytes = archive({ files: { '雪🌱.js': { offset: '0', size: 0 } } });
  const facts = inspect(bytes);
  assert.equal(facts?.status, 'ok');
  assert.equal(facts.entries[0].path.text, '雪🌱.js');
  const result = read(bytes, { path: '雪🌱.js' });
  assert.equal(result?.status, 'ok');
  assert.equal(result.view.length, 0);
  assert.equal(result.view.base64, '');
  assert.equal(result.view.sha256, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
});

test('listing pages large legitimate paths with exact length and path digest', () => {
  const path = `research-${'a'.repeat(8192)}.txt`;
  const bytes = archive({ files: { [path]: { offset: '0', size: 0 }, real: { offset: '0', size: 0 } } });
  const first = inspect(bytes, { offset: 0, limit: 1 });
  assert.equal(first?.status, 'ok');
  assert.equal(first.page.nextOffset, 1);
  assert.equal(first.entries[0].path.length, path.length);
  assert.equal(first.entries[0].path.sha256, sha(Buffer.from(path)));
  assert.equal(first.entries[0].path.truncated, true);
  assert.equal(first.entries[0].path.text, undefined);
  assert.ok(JSON.stringify(first).length < 3000);
  assert.equal(inspect(bytes, { offset: 1, limit: 1 })?.entries?.[0]?.path?.text, 'real');
  assert.equal(read(bytes, { path })?.status, 'ok');
  assert.equal(first.entries[0].decoy, undefined);
});

test('benign header growth beyond 16 MiB remains pageable and preserves real entry bytes', () => {
  const files = { 'package.json': { offset: '0', size: manifest.length } };
  for (let i = 0; i < 4100; i++) files[`legitimate-${'a'.repeat(4096)}-${i}`] = { offset: String(manifest.length), size: 0 };
  const bytes = archive({ files }, manifest);
  assert.ok(bytes.readUInt32LE(4) > 16 * 1024 * 1024);
  const facts = inspect(bytes);
  assert.equal(facts?.status, 'ok');
  assert.equal(facts.totalEntries, 4101);
  assert.equal(facts.entries.length, 20);
  assert.ok(JSON.stringify(facts).length < 20000);
  assert.equal(read(bytes, { path: 'package.json' })?.view?.base64, 'eyJtYWluIjoibWFpbi5qcyJ9');
});

for (const mutation of [
  b => b.subarray(0, 15),
  b => { b.writeUInt32LE(8, 0); return b; },
  b => { b.writeUInt32LE(b.readUInt32LE(8) + 4, 8); return b; },
  b => { b.writeUInt32LE(b.readUInt32LE(4) + 1, 4); return b; },
  b => { b.writeUInt32LE(0xffffffff, 12); return b; },
  b => { b.writeUInt32LE(0xfffffffc, 4); return b; },
  b => b.subarray(0, b.readUInt32LE(4) + 7),
]) test(`malformed or truncated pickle extents fail closed (${mutation.toString().slice(0, 56)})`, () => {
  assert.equal(inspect(mutation(Buffer.from(tiny())))?.status, 'error');
});

test('invalid JSON, invalid UTF-8, duplicate keys and wrong node shapes fail closed', () => {
  const invalidUtf8 = archive('{"files":{}}'); invalidUtf8[18] = 0xff;
  for (const bytes of [archive('{'), invalidUtf8, archive('{"files":{"a":{"size":0,"offset":"0"},"a":{"size":0,"offset":"0"}}}'),
    archive([]), archive({ files: [] }), archive({ files: { a: {} } }),
    archive({ files: { a: { files: {}, size: 1 } } }), archive({ files: { a: { offset: '0', size: 0, surprise: true } } })]) {
    assert.equal(inspect(bytes)?.status, 'error');
  }
});

for (const name of ['..', '.', '', '/etc', 'C:', '\\\\host', 'a/b', 'a\\b', 'a\0b', 'a.', 'a ', 'NUL']) {
  test(`unsafe/ambiguous path is refused (${JSON.stringify(name)})`, () => {
    assert.equal(inspect(archive({ files: { [name]: { size: 0, offset: '0' } } }))?.reason?.code, 'ASAR_UNSAFE_PATH');
    // A slash is invalid within a header segment but valid between selector segments.
    assert.equal(read(tiny(), { path: name })?.reason?.code, name === 'a/b' ? 'ASAR_ENTRY_NOT_FOUND' : 'ASAR_INVALID_SELECTOR');
  });
}

test('case and Unicode normalization collisions are reported as ambiguous', () => {
  for (const names of [['Readme', 'README'], ['é', 'e\u0301']]) {
    const bytes = archive({ files: Object.fromEntries(names.map(name => [name, { offset: '0', size: 0 }])) });
    assert.equal(inspect(bytes)?.reason?.code, 'ASAR_AMBIGUOUS_PATH');
  }
});

test('links and unpacked content remain unknown while a real packed member is readable', () => {
  const bytes = archive({ files: {
    real: { offset: '0', size: 1 }, alias: { link: 'real' }, external: { size: 7, unpacked: true },
  } }, Buffer.from('x'));
  assert.equal(inspect(bytes)?.status, 'unknown');
  assert.equal(inspect(bytes)?.totalEntries, 3);
  assert.equal(read(bytes, { path: 'alias' })?.reason?.code, 'ASAR_LINK_UNSUPPORTED');
  assert.equal(read(bytes, { path: 'external' })?.reason?.code, 'ASAR_UNPACKED_UNSUPPORTED');
  assert.equal(read(bytes, { path: 'real' })?.view?.base64, 'eA==');
  assert.equal(read(bytes, { path: 'real' })?.archiveScope, 'packed-entry-only');
});

test('unsafe link targets are invalid and are never followed', () => {
  for (const target of ['../escape', '/absolute', 'C:/host', '\\\\host', 'a\0b']) {
    assert.equal(inspect(archive({ files: { alias: { link: target } } }))?.status, 'error');
  }
});

test('overlapping ranges and noncanonical/unsafe numeric offsets or sizes fail closed', () => {
  const bad = [
    { files: { a: { offset: '0', size: 2 }, b: { offset: '1', size: 1 } } },
    ...['01', '-1', '1e0', ' 1', '9007199254740992', 0].map(offset => ({ files: { a: { offset, size: 0 } } })),
    ...[-1, 0.5, Number.MAX_SAFE_INTEGER + 1, '1'].map(size => ({ files: { a: { offset: '0', size } } })),
    { files: { a: { offset: '2', size: 1 } } },
  ];
  for (const header of bad) assert.equal(inspect(archive(header, Buffer.from('xx')))?.status, 'error');
});

test('configured header and entry admission limits fail unknown without partial-success claims', () => {
  const bytes = tiny();
  assert.equal(inspect(bytes, { maxHeaderBytes: 16 })?.reason?.code, 'ASAR_HEADER_LIMIT');
  assert.equal(read(bytes, { path: 'main.js' }, { maxHeaderBytes: 16 })?.status, 'unknown');
  assert.equal(inspect(bytes, { maxEntries: 1 })?.reason?.code, 'ASAR_ENTRY_LIMIT');
  assert.equal(inspect(bytes, { maxHeaderBytes: 64 * 1024 * 1024 + 1 })?.status, 'error');
  assert.equal(inspect(bytes, { maxEntries: 50001 })?.status, 'error');
  assert.equal(inspect(bytes, { limit: 101 })?.status, 'error');
  assert.equal(inspect(bytes, { offset: -1 })?.status, 'error');
});

test('more than 64 path segments is refused before expanding a deep tree', () => {
  let node = { offset: '0', size: 0 };
  for (let i = 0; i < 65; i++) node = { files: { [`d${i}`]: node } };
  assert.equal(inspect(archive(node))?.reason?.code, 'ASAR_DEPTH_LIMIT');
});

test('ordinary directories, empty pages and binary data do not require JavaScript interpretation', () => {
  const bytes = archive({ files: { folder: { files: { 'data.bin': { offset: '0', size: 4 } } } } }, Buffer.from([0, 255, 128, 1]));
  assert.equal(inspect(bytes)?.status, 'ok');
  assert.equal(read(bytes, { path: 'folder/data.bin' })?.view?.base64, 'AP+AAQ==');
  assert.equal(read(bytes, { path: 'folder' })?.reason?.code, 'ASAR_DIRECTORY_UNSUPPORTED');
  assert.equal(inspect(bytes, { offset: 99 })?.entries?.length, 0);
});

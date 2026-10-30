import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { inspectNative } from "../dist/native.js";
import { pe, elf, macho } from "./helpers/native-fixtures.mjs";
test("PE maps entry RVA to original executable bytes and preserves immutable input", () => {
  const b = pe(),
    copy = Buffer.from(b),
    r = inspectNative(b);
  assert.equal(r.status, "ok");
  assert.equal(r.format, "pe");
  assert.equal(r.entrypoint.fileOffset, 512);
  assert.equal(r.entrypoint.virtualAddress, "0x140001000");
  assert.equal(r.executableRanges[0].fileOffset, 512);
  assert.equal(r.executableRanges[0].size, 512);
  assert.equal(r.sourceSha256, createHash("sha256").update(copy).digest("hex"));
  assert.deepEqual(b, copy);
  assert.equal(
    inspectNative(pe({ bits: 32 })).entrypoint.virtualAddress,
    "0x401000",
  );
});
test("PE rejects short optional header, directory outside header, virtual ambiguity and raw overflow", () => {
  for (const mutate of [
    (b) => b.writeUInt16LE(24, 0x94),
    (b) => b.writeUInt32LE(17, 0x98 + 108),
    (b) => b.writeUInt32LE(0x1000, 0x1b0 + 12),
    (b) => b.writeUInt32LE(0xffffff00, 0x188 + 20),
    (b) => b.writeUInt32LE(0x1800, 0x188 + 8),
  ]) {
    const b = pe();
    mutate(b);
    assert.equal(inspectNative(b).status, "unknown");
  }
});
test("PE certificate bytes are separated from appended metadata and never assert signature validity", () => {
  const b = Buffer.concat([
    pe(),
    Buffer.alloc(16),
    Buffer.from("ordinary-overlay"),
  ]);
  b.writeUInt32LE(0x600, 0x98 + 112 + 32);
  b.writeUInt32LE(16, 0x98 + 112 + 36);
  b.writeUInt32LE(16, 0x600);
  b.writeUInt16LE(0x200, 0x604);
  b.writeUInt16LE(2, 0x606);
  const r = inspectNative(b);
  assert.equal(r.status, "ok");
  assert.equal(
    r.regions.find((x) => x.kind === "certificate").fileOffset,
    1536,
  );
  assert.equal(r.regions.find((x) => x.kind === "trailer").fileOffset, 1552);
  assert.equal(r.signatureStatus, "unknown");
});
test("entrypoint in non-executable or zero-fill bytes remains unknown", () => {
  const b = pe();
  b.writeUInt32LE(0x2000, 0x98 + 16);
  assert.equal(inspectNative(b).entrypoint.status, "unknown");
  b.writeUInt32LE(0x1000, 0x98 + 16);
  b.writeUInt32LE(0x400, 0x188 + 8);
  b.writeUInt32LE(0x1300, 0x98 + 16);
  assert.equal(inspectNative(b).entrypoint.status, "unknown");
});
test("ELF supports literal 32/64 endian layouts and excludes NOBITS from file extents", () => {
  for (const bits of [32, 64])
    for (const endian of ["little", "big"]) {
      const r = inspectNative(elf({ bits, endian }));
      assert.equal(r.status, "ok");
      assert.equal(r.bits, bits);
      assert.equal(r.entrypoint.fileOffset, 256);
      assert.equal(r.executableRanges[0].size, 16);
    }
  const r = inspectNative(elf({ nobits: true }));
  assert.equal(r.status, "ok");
  assert.equal(r.regions.find((x) => x.kind === "section").fileBacked, false);
});
test("ELF rejects extended counts, oversized integers, overlapping PT_LOADs and filesz over memsz", () => {
  for (const mutate of [
    (b) => b.writeUInt16LE(65535, 56),
    (b) => b.writeBigUInt64LE(0xffffffffffffffffn, 32),
    (b) => b.writeBigUInt64LE(1n, 104),
    (b) => {
      b.writeUInt16LE(2, 56);
      b.copy(b, 120, 64, 120);
    },
  ]) {
    const b = elf();
    mutate(b);
    assert.equal(inspectNative(b).status, "unknown");
  }
});
test("Mach-O validates command extents and maps LC_MAIN through executable segment", () => {
  const b = macho(),
    r = inspectNative(b);
  assert.equal(r.status, "ok");
  assert.equal(r.format, "macho");
  assert.equal(r.entrypoint.fileOffset, 256);
  assert.equal(r.entrypoint.virtualAddress, "0x100000100");
  for (const mutate of [
    (x) => x.writeUInt32LE(4, 36),
    (x) => x.writeUInt32LE(97, 20),
    (x) => x.writeBigUInt64LE(0x1000n, 112),
    (x) => x.writeUInt32LE(0xcafebabe, 0),
  ]) {
    const c = macho();
    mutate(c);
    assert.equal(inspectNative(c).status, "unknown");
  }
});
test("bounded paging, suspicious metadata and benign fuse lookalikes keep semantic authority unknown", () => {
  const sentinel = "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX",
    b = Buffer.concat([
      pe(),
      Buffer.from(
        sentinel + "\x01\x0830110011" + "/rustc/" + "a".repeat(40) + "/",
      ),
    ]);
  const r = inspectNative(b, { offset: 1, limit: 1 });
  assert.equal(r.status, "ok");
  assert.equal(r.regions.length, 1);
  assert.equal(r.pagination.limit, 1);
  assert.equal(r.metadata.semanticAuthority, "unknown");
  assert.equal(
    r.metadata.observations.find((x) => x.marker === "electron-fuse-sentinel")
      .count,
    1,
  );
  assert.equal(r.metadata.electronHardening, "unknown");
  assert.equal(inspectNative(pe(), { limit: 101 }).status, "error");
  assert.equal(inspectNative(pe(), { offset: -1 }).status, "error");
  assert.equal(inspectNative(Buffer.alloc(0)).status, "unknown");
  const cap = inspectNative(
    Buffer.concat([pe(), Buffer.from(sentinel.repeat(130))]),
  );
  assert.equal(cap.status, "unknown");
  assert.match(cap.reason, /cap/i);
});
test("PE refuses directory RVAs beyond backed image bytes and directory RVA arithmetic overflow", () => {
  for (const [rva, size] of [
    [0x2100, 0x300],
    [0xfffffff0, 32],
    [0x800, 16],
  ]) {
    const b = pe();
    b.writeUInt32LE(rva, 0x98 + 112);
    b.writeUInt32LE(size, 0x98 + 116);
    assert.equal(inspectNative(b).status, "unknown");
  }
});
test("all truncated native prefixes refuse without throwing or fabricated executable ranges", () => {
  for (const fixture of [pe(), elf(), macho()])
    for (const end of [1, 2, 4, 15, 31, 63, 95, 127]) {
      const r = inspectNative(fixture.subarray(0, end));
      assert.equal(r.status, "unknown");
      assert.ok(!r.executableRanges || r.executableRanges.length === 0);
    }
});
test("paging rejects arithmetic overflow and null values, including non-object arrays", () => {
  for (const options of [
    { offset: Number.MAX_SAFE_INTEGER },
    { offset: null },
    { limit: null },
    [],
  ])
    assert.equal(inspectNative(pe(), options).status, "error");
});
test("thin Mach-O32 big and little endian preserve original LC_MAIN coordinates", () => {
  for (const le of [true, false]) {
    const b = Buffer.alloc(512),
      u32 = (v, p) => (le ? b.writeUInt32LE(v, p) : b.writeUInt32BE(v, p)),
      u64 = (v, p) =>
        le
          ? b.writeBigUInt64LE(BigInt(v), p)
          : b.writeBigUInt64BE(BigInt(v), p);
    u32(0xfeedface, 0);
    u32(7, 4);
    u32(2, 12);
    u32(2, 16);
    u32(80, 20);
    u32(1, 28);
    u32(56, 32);
    b.write("__TEXT", 36);
    u32(0x1000, 52);
    u32(512, 56);
    u32(0, 60);
    u32(512, 64);
    u32(7, 68);
    u32(5, 72);
    u32(0x80000028, 84);
    u32(24, 88);
    u64(256, 92);
    const r = inspectNative(b);
    assert.equal(r.status, "ok");
    assert.equal(r.bits, 32);
    assert.equal(r.entrypoint.virtualAddress, "0x1100");
    assert.equal(r.entrypoint.fileOffset, 256);
  }
});
test("input cap refuses oversized Buffer before hashing or layout work", () => {
  const r = inspectNative(Buffer.alloc(64 * 1024 * 1024 + 1));
  assert.equal(r.status, "unknown");
  assert.equal(r.sourceSha256, null);
  assert.match(r.reason, /cap/);
});
test("PE refuses invalid loader alignments and a raw extent misaligned to file alignment", () => {
  for (const mutate of [
    (b) => b.writeUInt32LE(0, 0x98 + 32),
    (b) => b.writeUInt32LE(513, 0x98 + 36),
    (b) => b.writeUInt32LE(0x180, 0x188 + 16),
    (b) => b.writeUInt32LE(0x14000001, 0x98 + 24),
  ]) {
    const b = pe();
    mutate(b);
    assert.equal(inspectNative(b).status, "unknown");
  }
});

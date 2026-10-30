import test from "node:test";
import assert from "node:assert/strict";
import { inspectNative } from "../dist/native.js";
import { pe, elf } from "./helpers/native-fixtures.mjs";

// Independent literal fields for the reviewed admission invariants. No provider/target execution.
function segment({
  bits = 64,
  endian = "little",
  high = false,
  sections = [],
  filetype = 2,
  ceiling = false,
} = {}) {
  const b = Buffer.alloc(0x800),
    le = endian === "little",
    wide = bits === 64;
  const u32 = (v, p) => (le ? b.writeUInt32LE(v, p) : b.writeUInt32BE(v, p));
  const word = (v, p) =>
    wide
      ? le
        ? b.writeBigUInt64LE(BigInt(v), p)
        : b.writeBigUInt64BE(BigInt(v), p)
      : u32(Number(v), p);
  const header = wide ? 32 : 28,
    base = wide ? 72 : 56,
    ss = wide ? 80 : 68;
  const address = ceiling
    ? (1n << BigInt(bits)) - 0x1000n
    : wide
      ? 0x100000000n
      : 0x1000n;
  u32(wide ? 0xfeedfacf : 0xfeedface, 0);
  u32(wide ? 0x1000007 : 7, 4);
  u32(filetype, 12);
  u32(1, 16);
  u32(base + sections.length * ss, 20);
  u32(wide ? 0x19 : 1, header);
  u32(base + sections.length * ss, header + 4);
  b.write("__TEXT", header + 8);
  word(address, header + 24);
  word(0x1000, header + (wide ? 32 : 28));
  word(0, header + (wide ? 40 : 32));
  word(0x800, header + (wide ? 48 : 36));
  u32(7, header + (wide ? 56 : 40));
  u32(5, header + (wide ? 60 : 44));
  u32(sections.length, header + (wide ? 64 : 48));
  u32(high ? 1 : 0, header + (wide ? 68 : 52));
  for (const [index, s] of sections.entries()) {
    const p = header + base + index * ss;
    b.write("__s" + index, p);
    b.write("__TEXT", p + 16);
    word(address + BigInt(s.vm), p + 32);
    word(s.size ?? 16, p + (wide ? 40 : 36));
    u32(s.file ?? 0, p + (wide ? 48 : 40));
    u32(s.zeroFill ? 1 : 0, p + (wide ? 64 : 56));
  }
  return b;
}
function lowPe(bits, matching) {
  const original = pe({ bits }),
    b = Buffer.alloc(0x2200);
  original.copy(b);
  b.writeUInt32LE(0x200, 0x98 + 32);
  if (matching) {
    const sections = bits === 64 ? 0x188 : 0x178;
    b.writeUInt32LE(0x1000, sections + 20);
    b.writeUInt32LE(0x2000, sections + 60);
    original.subarray(0x200, 0x400).copy(b, 0x1000);
    original.subarray(0x400, 0x600).copy(b, 0x2000);
  }
  return b;
}
function allocatedElf({ bits, endian, type, address, size, alloc = true }) {
  const b = elf({ bits, endian }),
    le = endian === "little",
    wide = bits === 64;
  const u16 = (v, p) => (le ? b.writeUInt16LE(v, p) : b.writeUInt16BE(v, p)),
    u32 = (v, p) => (le ? b.writeUInt32LE(v, p) : b.writeUInt32BE(v, p));
  const word = (v, p) =>
    wide
      ? le
        ? b.writeBigUInt64LE(BigInt(v), p)
        : b.writeBigUInt64BE(BigInt(v), p)
      : u32(Number(v), p);
  word(0x200, wide ? 40 : 32);
  u16(wide ? 64 : 40, wide ? 58 : 46);
  u16(2, wide ? 60 : 48);
  const p = 0x200 + (wide ? 64 : 40);
  u32(type, p + 4);
  word(alloc ? 2 : 0, p + 8);
  word(address, p + (wide ? 16 : 12));
  word(type === 8 ? 0x100000 : 0x300, p + (wide ? 24 : 16));
  word(size, p + (wide ? 32 : 20));
  return b;
}
function refuses(b, reason) {
  const copy = Buffer.from(b),
    r = inspectNative(b, { limit: 100 });
  assert.equal(r.status, "unknown");
  assert.match(r.reason, reason);
  assert.deepEqual(r.regions, []);
  assert.deepEqual(r.executableRanges, []);
  assert.deepEqual(b, copy);
}
for (const bits of [32, 64])
  for (const endian of ["little", "big"]) {
    test(`I1 SG_HIGHVM ${bits}/${endian} refuses before wrong executable mapping; ordinary boundary control admitted`, () => {
      const normal = inspectNative(segment({ bits, endian, ceiling: true }));
      assert.equal(normal.status, "ok");
      assert.equal(
        normal.executableRanges[0].virtualAddress,
        bits === 64 ? "0xfffffffffffff000" : "0xfffff000",
      );
      refuses(segment({ bits, endian, high: true, filetype: 4 }), /SG_HIGHVM/);
    });
    for (const defect of ["virtual-overlap", "translation", "object"])
      test(`I3 ${defect} ${bits}/${endian} refuses; coherent disjoint sections retain original translation`, () => {
        const coherent = segment({
          bits,
          endian,
          ceiling: true,
          sections: [
            { vm: 0x300, file: 0x300 },
            { vm: 0x400, file: 0x400 },
          ],
        });
        const good = inspectNative(coherent, { limit: 100 });
        assert.equal(good.status, "ok");
        assert.equal(
          good.regions.filter((r) => r.kind === "section")[1].fileOffset,
          0x400,
        );
        if (defect === "virtual-overlap")
          refuses(
            segment({
              bits,
              endian,
              sections: [
                { vm: 0x300, file: 0x300, size: 0x20 },
                { vm: 0x310, size: 0x10, zeroFill: true },
              ],
            }),
            /section.*virtual.*overlap/i,
          );
        else if (defect === "translation")
          refuses(
            segment({
              bits,
              endian,
              sections: [
                { vm: 0x300, file: 0x300 },
                { vm: 0x500, file: 0x400 },
              ],
            }),
            /section.*translation/i,
          );
        else refuses(segment({ bits, endian, filetype: 1 }), /MH_OBJECT/);
      });
    for (const type of [1, 8])
      test(`I4 SHF_ALLOC type${type} ${bits}/${endian} width overflow refused; exact half-open ceiling remains valid`, () => {
        const ceiling = 1n << BigInt(bits),
          opts = { bits, endian, type, address: ceiling - 16n, size: 16 };
        const b = allocatedElf(opts),
          good = inspectNative(b, { limit: 100 });
        assert.equal(good.status, "ok");
        const s = good.regions.find((r) => r.kind === "section");
        assert.equal(
          s.virtualAddress,
          bits === 64 ? "0xfffffffffffffff0" : "0xfffffff0",
        );
        assert.equal(s.size, 16);
        assert.equal(s.fileBacked, type !== 8);
        if (type === 8) {
          assert.equal(Object.hasOwn(s, "sha256"), false);
          assert.equal(Object.hasOwn(s, "fileOffset"), false);
        }
        refuses(
          allocatedElf({ ...opts, size: 0x100 }),
          /ELF allocated section.*overflow/i,
        );
        const notAllocated = inspectNative(
          allocatedElf({ ...opts, size: 0x100, alloc: false }),
        );
        assert.equal(notAllocated.status, "ok");
      });
  }
for (const bits of [32, 64])
  test(`I2 low-alignment PE${bits} requires raw offset equals RVA, matching and page-aligned controls retained`, () => {
    const good = inspectNative(lowPe(bits, true));
    assert.equal(good.status, "ok");
    assert.equal(good.entrypoint.fileOffset, 0x1000);
    assert.equal(inspectNative(pe({ bits })).status, "ok");
    refuses(lowPe(bits, false), /low-alignment.*raw.*RVA/i);
  });
test("I2 unsupported PE page-size architecture refuses rather than inferring a low-alignment mapping", () => {
  const b = lowPe(64, true);
  b.writeUInt16LE(0x200, 0x84);
  refuses(b, /page-size.*unsupported/i);
});

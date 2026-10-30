// Independently authored literal layouts; no upstream tests or challenge data.
export function pe({ multiplier = 3, addend = 7, bits = 64 } = {}) {
  const b = Buffer.alloc(0x600);
  b.write("MZ");
  b.writeUInt32LE(0x80, 0x3c);
  b.write("PE\0\0", 0x80, "latin1");
  const optSize = bits === 64 ? 240 : 224,
    o = 0x98,
    s = o + optSize;
  b.writeUInt16LE(bits === 64 ? 0x8664 : 0x14c, 0x84);
  b.writeUInt16LE(2, 0x86);
  b.writeUInt16LE(optSize, 0x94);
  b.writeUInt16LE(0x22, 0x96);
  b.writeUInt16LE(bits === 64 ? 0x20b : 0x10b, o);
  b.writeUInt32LE(0x1000, o + 16);
  if (bits === 64) b.writeBigUInt64LE(0x140000000n, o + 24);
  else b.writeUInt32LE(0x400000, o + 28);
  b.writeUInt32LE(0x1000, o + 32);
  b.writeUInt32LE(0x200, o + 36);
  b.writeUInt32LE(0x3000, o + 56);
  b.writeUInt32LE(0x200, o + 60);
  b.writeUInt16LE(3, o + 68);
  b.writeUInt32LE(16, o + (bits === 64 ? 108 : 92));
  b.writeUInt32LE(0x2000, o + (bits === 64 ? 112 : 96));
  b.writeUInt32LE(0x100, o + (bits === 64 ? 116 : 100));
  for (const [i, name, rva, raw, flags] of [
    [0, ".text", 0x1000, 0x200, 0x60000020],
    [1, ".edata", 0x2000, 0x400, 0x40000040],
  ]) {
    const p = s + i * 40;
    b.write(name, p);
    b.writeUInt32LE(0x200, p + 8);
    b.writeUInt32LE(rva, p + 12);
    b.writeUInt32LE(0x200, p + 16);
    b.writeUInt32LE(raw, p + 20);
    b.writeUInt32LE(flags, p + 36);
  }
  Buffer.from([0x6b, 0xc1, multiplier, 0x83, 0xc0, addend, 0xc3]).copy(
    b,
    0x200,
  );
  // IMAGE_EXPORT_DIRECTORY and single named business entrypoint.
  for (const [off, val] of [
    [12, 0x2060],
    [16, 1],
    [20, 1],
    [24, 1],
    [28, 0x2040],
    [32, 0x2044],
    [36, 0x2048],
  ])
    b.writeUInt32LE(val, 0x400 + off);
  b.writeUInt32LE(0x1000, 0x440);
  b.writeUInt32LE(0x2070, 0x444);
  b.write("own-native.exe\0", 0x460);
  b.write("score\0", 0x470);
  return b;
}
export function elf({ bits = 64, endian = "little", nobits = false } = {}) {
  const b = Buffer.alloc(0x400),
    le = endian === "little";
  b.set([127, 69, 76, 70, bits === 64 ? 2 : 1, le ? 1 : 2, 1]);
  const u16 = (v, p) => (le ? b.writeUInt16LE(v, p) : b.writeUInt16BE(v, p)),
    u32 = (v, p) => (le ? b.writeUInt32LE(v, p) : b.writeUInt32BE(v, p)),
    u64 = (v, p) =>
      le ? b.writeBigUInt64LE(BigInt(v), p) : b.writeBigUInt64BE(BigInt(v), p);
  u16(2, 16);
  u16(bits === 64 ? 62 : 3, 18);
  u32(1, 20);
  if (bits === 64) {
    u64(0x400100, 24);
    u64(64, 32);
    u64(nobits ? 0x200 : 0, 40);
    u16(64, 52);
    u16(56, 54);
    u16(1, 56);
    u16(64, 58);
    u16(nobits ? 2 : 0, 60);
    u32(1, 64);
    u32(5, 68);
    u64(0x100, 72);
    u64(0x400100, 80);
    u64(16, 96);
    u64(32, 104);
    u64(1, 112);
    if (nobits) {
      u32(8, 0x244);
      u64(0x100000, 0x258);
      u64(0x9000, 0x260);
    }
  } else {
    u32(0x8048100, 24);
    u32(52, 28);
    u16(52, 40);
    u16(32, 42);
    u16(1, 44);
    u16(40, 46);
    u32(1, 52);
    u32(0x100, 56);
    u32(0x8048100, 60);
    u32(16, 68);
    u32(32, 72);
    u32(5, 76);
    u32(1, 80);
  }
  b[0x100] = 0xc3;
  return b;
}
export function macho() {
  const b = Buffer.alloc(0x200);
  b.writeUInt32LE(0xfeedfacf, 0);
  b.writeUInt32LE(0x1000007, 4);
  b.writeUInt32LE(2, 12);
  b.writeUInt32LE(2, 16);
  b.writeUInt32LE(96, 20);
  b.writeUInt32LE(0x19, 32);
  b.writeUInt32LE(72, 36);
  b.write("__TEXT", 40);
  b.writeBigUInt64LE(0x100000000n, 56);
  b.writeBigUInt64LE(0x200n, 64);
  b.writeBigUInt64LE(0n, 72);
  b.writeBigUInt64LE(0x200n, 80);
  b.writeUInt32LE(7, 88);
  b.writeUInt32LE(5, 92);
  b.writeUInt32LE(0x80000028, 104);
  b.writeUInt32LE(24, 108);
  b.writeBigUInt64LE(0x100n, 112);
  b[0x100] = 0xc3;
  return b;
}

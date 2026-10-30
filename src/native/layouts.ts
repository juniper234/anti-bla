import { createHash } from "node:crypto";
type Data = Record<string, unknown>;
export interface NativeMapping {
  index: number;
  fileOffset: number;
  size: number;
  address: bigint;
  memorySize: bigint;
  executable: boolean;
}
export interface NativeLayout {
  format: string;
  bits: number;
  endian: string;
  architecture: number;
  mappings: NativeMapping[];
  regions: Data[];
  entrypoint: Data;
}
export class NativeRefusal extends Error {}
const sha = (b: Buffer) => createHash("sha256").update(b).digest("hex");
const hex = (n: bigint) => `0x${n.toString(16)}`;
function check(ok: unknown, message: string): asserts ok {
  if (!ok) throw new NativeRefusal(message);
}
function safe(n: bigint, label: string): number {
  check(
    n <= BigInt(Number.MAX_SAFE_INTEGER),
    `${label} exceeds safe integer range`,
  );
  return Number(n);
}
function extent(b: Buffer, offset: number, size: number, label: string): void {
  check(
    Number.isSafeInteger(offset) &&
      Number.isSafeInteger(size) &&
      offset >= 0 &&
      size >= 0 &&
      offset <= b.length &&
      size <= b.length - offset,
    `${label} file extent out of bounds`,
  );
}
const overlap = (a: number, as: number, b: number, bs: number) =>
  as > 0 && bs > 0 && a < b + bs && b < a + as;
function disjoint(
  ranges: Array<{ offset: number; size: number }>,
  label: string,
): void {
  const sorted = ranges
    .filter((r) => r.size > 0)
    .sort((a, b) => a.offset - b.offset);
  for (let i = 1; i < sorted.length; i++)
    check(
      sorted[i - 1]!.offset + sorted[i - 1]!.size <= sorted[i]!.offset,
      `${label} overlap or ambiguous mapping`,
    );
}
function validateMappings(mappings: NativeMapping[]): void {
  disjoint(
    mappings.map((m) => ({ offset: m.fileOffset, size: m.size })),
    "mapped file ranges",
  );
  const sorted = mappings
    .filter((m) => m.memorySize > 0n)
    .sort((a, b) =>
      a.address < b.address ? -1 : a.address > b.address ? 1 : 0,
    );
  for (let i = 1; i < sorted.length; i++)
    check(
      sorted[i - 1]!.address + sorted[i - 1]!.memorySize <= sorted[i]!.address,
      "mapped virtual ranges overlap or ambiguous mapping",
    );
}
function name(b: Buffer, offset: number, size: number): Data {
  extent(b, offset, size, "name");
  const raw = b.subarray(offset, offset + size);
  return {
    preview: raw.subarray(0, 64).toString("utf8"),
    previewHex: raw.subarray(0, 64).toString("hex"),
    byteLength: size,
    sha256: sha(raw),
    fileOffset: offset,
    previewComplete: size <= 64,
  };
}
function fixedName(b: Buffer, offset: number, size: number): Data {
  const end = b.subarray(offset, offset + size).indexOf(0);
  return name(b, offset, end < 0 ? size : end);
}
export function nativeRegion(
  b: Buffer,
  kind: string,
  offset: number,
  size: number,
  extra: Data = {},
): Data {
  extent(b, offset, size, kind);
  return {
    kind,
    fileOffset: offset,
    size,
    semanticAuthority: "unknown",
    ...extra,
  };
}
function resolveAddress(
  address: bigint | undefined,
  mappings: NativeMapping[],
): Data {
  if (address === undefined)
    return {
      status: "unknown",
      reason: "entrypoint declaration unavailable or unsupported",
    };
  const matches = mappings.filter(
    (m) =>
      m.executable &&
      address >= m.address &&
      address < m.address + BigInt(m.size),
  );
  return matches.length === 1
    ? {
        status: "ok",
        virtualAddress: hex(address),
        fileOffset:
          matches[0]!.fileOffset + Number(address - matches[0]!.address),
        mappingIndex: matches[0]!.index,
        reachability: "declared-entrypoint-only",
      }
    : {
        status: "unknown",
        virtualAddress: hex(address),
        reason: "entrypoint lacks unique file-backed executable mapping",
      };
}
export function parsePe(b: Buffer): NativeLayout {
  extent(b, 0, 64, "DOS header");
  const p = b.readUInt32LE(60);
  check(p >= 64, "PE header overlaps DOS header");
  extent(b, p, 24, "PE header");
  check(
    b.subarray(p, p + 4).equals(Buffer.from("PE\0\0")),
    "PE signature invalid",
  );
  const machine = b.readUInt16LE(p + 4),
    count = b.readUInt16LE(p + 6),
    os = b.readUInt16LE(p + 20),
    o = p + 24;
  check(count > 0 && count <= 512, "PE section count cap or empty table");
  extent(b, o, os, "PE optional header");
  check(os >= 2, "PE optional header too short");
  const magic = b.readUInt16LE(o),
    bits = magic === 0x20b ? 64 : magic === 0x10b ? 32 : 0;
  check(bits, "unsupported PE optional header magic");
  const minimum = bits === 64 ? 112 : 96;
  check(os >= minimum, "PE optional header truncated");
  const directoryCount = b.readUInt32LE(o + minimum - 4);
  check(directoryCount <= 16, "PE data directory count cap");
  check(
    minimum + directoryCount * 8 <= os,
    "PE directories outside optional header",
  );
  const imageBase =
      bits === 64 ? b.readBigUInt64LE(o + 24) : BigInt(b.readUInt32LE(o + 28)),
    entry = BigInt(b.readUInt32LE(o + 16)),
    sectionAt = o + os,
    headers = b.readUInt32LE(o + 60),
    imageSize = b.readUInt32LE(o + 56);
  const sectionAlignment = b.readUInt32LE(o + 32),
    fileAlignment = b.readUInt32LE(o + 36);
  // Page-size-sensitive admission is currently qualified only for x86/x64.
  // Other machines must not inherit an assumed 4KiB loader rule.
  check(
    machine === 0x14c || machine === 0x8664,
    "PE machine page-size admission unsupported",
  );
  const powerOfTwo = (n: number) =>
    n > 0 && (BigInt(n) & (BigInt(n) - 1n)) === 0n;
  check(
    powerOfTwo(sectionAlignment) &&
      powerOfTwo(fileAlignment) &&
      sectionAlignment >= fileAlignment,
    "PE loader alignment invalid",
  );
  check(
    sectionAlignment < 4096
      ? fileAlignment === sectionAlignment
      : fileAlignment >= 512 && fileAlignment <= 65536,
    "PE file alignment unsupported",
  );
  check(
    imageBase % 65536n === 0n &&
      headers % fileAlignment === 0 &&
      imageSize % sectionAlignment === 0,
    "PE image/header alignment invalid",
  );
  extent(b, sectionAt, count * 40, "PE sections");
  check(
    headers >= sectionAt + count * 40 && headers <= b.length,
    "PE SizeOfHeaders invalid",
  );
  const mappings: NativeMapping[] = [],
    regions: Data[] = [nativeRegion(b, "headers", 0, headers)];
  for (let i = 0; i < count; i++) {
    const s = sectionAt + i * 40,
      vs = b.readUInt32LE(s + 8),
      rva = b.readUInt32LE(s + 12),
      size = b.readUInt32LE(s + 16),
      offset = b.readUInt32LE(s + 20),
      flags = b.readUInt32LE(s + 36),
      memorySize = Math.max(vs, size);
    extent(b, offset, size, `PE section ${i}`);
    check(
      sectionAlignment >= 4096 || size === 0 || offset === rva,
      "PE low-alignment section raw offset must equal RVA",
    );
    check(
      rva % sectionAlignment === 0 &&
        (size === 0 ||
          (offset % fileAlignment === 0 && size % fileAlignment === 0)),
      "PE section alignment invalid",
    );
    check(size === 0 || offset >= headers, "PE section overlaps headers");
    check(
      memorySize === 0 || rva >= headers,
      "PE section virtual extent overlaps headers",
    );
    check(
      rva + memorySize <= 0x100000000 && rva + memorySize <= imageSize,
      "PE section exceeds virtual image extent",
    );
    check(
      imageBase + BigInt(rva + memorySize) <= 1n << BigInt(bits),
      "PE virtual address overflow",
    );
    const m = {
      index: i,
      fileOffset: offset,
      size,
      address: imageBase + BigInt(rva),
      memorySize: BigInt(memorySize),
      executable: (flags & 0x20000000) !== 0,
    };
    mappings.push(m);
    regions.push(
      nativeRegion(b, "section", offset, size, {
        index: i,
        name: fixedName(b, s, 8),
        flags,
        executable: m.executable,
        virtualAddress: hex(m.address),
        memorySize: hex(m.memorySize),
        fileBacked: size > 0,
      }),
    );
  }
  validateMappings(mappings);
  for (let i = 0; i < directoryCount; i++) {
    if (i === 4) continue;
    const rva = b.readUInt32LE(o + minimum + i * 8),
      size = b.readUInt32LE(o + minimum + i * 8 + 4);
    check((rva === 0) === (size === 0), "PE directory RVA/size incomplete");
    if (!size) continue;
    check(rva + size <= 0x100000000, "PE directory RVA overflow");
    const start = imageBase + BigInt(rva),
      fitsHeader = rva < headers && rva + size <= headers,
      admitted = mappings.filter(
        (m) =>
          start >= m.address &&
          start + BigInt(size) <= m.address + BigInt(m.size),
      );
    check(
      fitsHeader || admitted.length === 1,
      "PE directory lacks unique backed RVA extent",
    );
  }
  const imageEnd = Math.max(
    headers,
    ...mappings.map((m) => m.fileOffset + m.size),
  );
  let certOffset = 0,
    certSize = 0;
  if (directoryCount > 4) {
    certOffset = b.readUInt32LE(o + minimum + 32);
    certSize = b.readUInt32LE(o + minimum + 36);
  }
  check(
    (certOffset === 0) === (certSize === 0),
    "PE certificate extent incomplete",
  );
  if (certSize) {
    extent(b, certOffset, certSize, "PE certificate table");
    check(
      certOffset % 8 === 0 && certOffset >= imageEnd,
      "PE certificate alignment or image overlap",
    );
    let c = certOffset,
      n = 0;
    while (c < certOffset + certSize) {
      check(++n <= 512, "PE certificate count cap");
      check(c + 8 <= certOffset + certSize, "PE certificate header truncated");
      const size = b.readUInt32LE(c);
      check(
        size >= 8 && size <= certOffset + certSize - c,
        "PE certificate length invalid",
      );
      const padded = Math.ceil(size / 8) * 8;
      check(
        padded <= certOffset + certSize - c,
        "PE certificate padding exceeds table",
      );
      c += padded;
    }
    if (certOffset > imageEnd)
      regions.push(nativeRegion(b, "trailer", imageEnd, certOffset - imageEnd));
    regions.push(
      nativeRegion(b, "certificate", certOffset, certSize, {
        signatureStatus: "unknown",
        certificates: n,
      }),
    );
    if (certOffset + certSize < b.length)
      regions.push(
        nativeRegion(
          b,
          "trailer",
          certOffset + certSize,
          b.length - certOffset - certSize,
        ),
      );
  } else if (imageEnd < b.length)
    regions.push(nativeRegion(b, "trailer", imageEnd, b.length - imageEnd));
  return {
    format: "pe",
    bits,
    endian: "little",
    architecture: machine,
    mappings,
    regions,
    entrypoint: resolveAddress(imageBase + entry, mappings),
  };
}
export function parseElf(b: Buffer): NativeLayout {
  extent(b, 0, 16, "ELF identity");
  const bits = b[4] === 2 ? 64 : b[4] === 1 ? 32 : 0,
    endian = b[5] === 1 ? "little" : b[5] === 2 ? "big" : "unknown";
  check(
    bits && endian !== "unknown" && b[6] === 1,
    "unsupported ELF class/endian/version",
  );
  const wide = bits === 64,
    header = wide ? 64 : 52;
  extent(b, 0, header, "ELF header");
  const u16 = (p: number) =>
      endian === "little" ? b.readUInt16LE(p) : b.readUInt16BE(p),
    u32 = (p: number) =>
      endian === "little" ? b.readUInt32LE(p) : b.readUInt32BE(p),
    u64 = (p: number) =>
      endian === "little" ? b.readBigUInt64LE(p) : b.readBigUInt64BE(p),
    word = (p: number) => (wide ? u64(p) : BigInt(u32(p)));
  check(u32(20) === 1, "ELF version unsupported");
  const entry = word(24),
    phoff = safe(word(wide ? 32 : 28), "ELF program offset"),
    shoff = safe(word(wide ? 40 : 32), "ELF section offset"),
    phsize = u16(wide ? 54 : 42),
    phcount = u16(wide ? 56 : 44),
    shsize = u16(wide ? 58 : 46),
    shcount = u16(wide ? 60 : 48),
    strIndex = u16(wide ? 62 : 50);
  check(u16(wide ? 52 : 40) === header, "ELF header size mismatch");
  check(
    phcount !== 65535 && strIndex !== 65535 && !(shoff > 0 && shcount === 0),
    "ELF extended counts unsupported",
  );
  check(phcount <= 512 && shcount <= 512, "ELF table count cap");
  check(
    (phcount === 0) === (phoff === 0) && (shcount === 0) === (shoff === 0),
    "ELF table offset/count mismatch",
  );
  check(strIndex === 0 || strIndex < shcount, "ELF string table index invalid");
  if (phcount) {
    check(
      phsize === (wide ? 56 : 32) && phoff >= header,
      "ELF program entry size/offset unsupported",
    );
    extent(b, phoff, phsize * phcount, "ELF program table");
  }
  if (shcount) {
    check(
      shsize === (wide ? 64 : 40) && shoff >= header,
      "ELF section entry size/offset unsupported",
    );
    extent(b, shoff, shsize * shcount, "ELF section table");
  }
  check(
    !overlap(phoff, phsize * phcount, shoff, shsize * shcount),
    "ELF tables overlap",
  );
  const mappings: NativeMapping[] = [],
    regions: Data[] = [nativeRegion(b, "headers", 0, header)],
    sections: Array<{
      type: number;
      offset: number;
      size: number;
      name: number;
      flags: bigint;
      address: bigint;
    }> = [];
  let end = Math.max(
    header,
    phoff + phsize * phcount,
    shoff + shsize * shcount,
  );
  for (let i = 0; i < phcount; i++) {
    const p = phoff + i * phsize,
      type = u32(p),
      flags = u32(p + (wide ? 4 : 24)),
      offset = safe(word(p + (wide ? 8 : 4)), "ELF segment offset"),
      address = word(p + (wide ? 16 : 8)),
      size = safe(word(p + (wide ? 32 : 16)), "ELF segment size"),
      mem = word(p + (wide ? 40 : 20)),
      align = word(p + (wide ? 48 : 28));
    extent(b, offset, size, `ELF segment ${i}`);
    check(
      align <= 1n || (align & (align - 1n)) === 0n,
      "ELF segment alignment not power of two",
    );
    if (type === 1) {
      check(BigInt(size) <= mem, "ELF PT_LOAD filesz exceeds memsz");
      check(address + mem <= 1n << BigInt(bits), "ELF virtual extent overflow");
      if (align > 1n)
        check(
          address % align === BigInt(offset) % align,
          "ELF PT_LOAD alignment mismatch",
        );
      mappings.push({
        index: i,
        fileOffset: offset,
        size,
        address,
        memorySize: mem,
        executable: (flags & 1) !== 0,
      });
    }
    regions.push(
      nativeRegion(b, "segment", offset, size, {
        index: i,
        type,
        flags,
        virtualAddress: hex(address),
        memorySize: hex(mem),
        executable: type === 1 && (flags & 1) !== 0,
        fileBacked: size > 0,
      }),
    );
    end = Math.max(end, offset + size);
  }
  validateMappings(mappings);
  for (let i = 0; i < shcount; i++) {
    const p = shoff + i * shsize,
      type = u32(p + 4),
      offset = safe(word(p + (wide ? 24 : 16)), "ELF section offset"),
      size = safe(word(p + (wide ? 32 : 20)), "ELF section size"),
      flags = word(p + 8),
      address = word(p + (wide ? 16 : 12));
    // Allocated sections describe memory even when SHT_NOBITS has no bytes
    // in the file. Use wide arithmetic; the half-open end may equal 2^bits.
    if ((flags & 2n) !== 0n)
      check(
        address + BigInt(size) <= 1n << BigInt(bits),
        "ELF allocated section virtual extent overflow",
      );
    if (type !== 0 && type !== 8) {
      extent(b, offset, size, `ELF section ${i}`);
      check(
        !overlap(offset, size, shoff, shsize * shcount) &&
          !overlap(offset, size, phoff, phsize * phcount) &&
          !overlap(offset, size, 0, header),
        "ELF section overlaps structure",
      );
      end = Math.max(end, offset + size);
    }
    sections.push({ type, offset, size, name: u32(p), flags, address });
  }
  disjoint(
    sections
      .filter((s) => s.type !== 0 && s.type !== 8)
      .map((s) => ({ offset: s.offset, size: s.size })),
    "ELF sections",
  );
  const strings = strIndex ? sections[strIndex] : undefined;
  if (strings) check(strings.type === 3, "ELF section names require STRTAB");
  for (let i = 1; i < sections.length; i++) {
    const s = sections[i]!;
    let label: Data | undefined;
    if (strings) {
      check(s.name < strings.size, "ELF section name offset invalid");
      const start = strings.offset + s.name,
        max = Math.min(strings.offset + strings.size, start + 4096);
      let finish = start;
      while (finish < max && b[finish] !== 0) finish++;
      check(finish < max, "ELF name scan cap or unterminated name");
      label = name(b, start, finish - start);
    }
    const fileBacked = s.type !== 0 && s.type !== 8;
    regions.push(
      fileBacked
        ? nativeRegion(b, "section", s.offset, s.size, {
            index: i,
            ...(label ? { name: label } : {}),
            type: s.type,
            flags: hex(s.flags),
            virtualAddress: hex(s.address),
            fileBacked,
          })
        : {
            kind: "section",
            index: i,
            ...(label ? { name: label } : {}),
            type: s.type,
            declaredFileOffset: s.offset,
            size: s.size,
            fileBacked: false,
            virtualAddress: hex(s.address),
            semanticAuthority: "unknown",
          },
    );
  }
  if (end < b.length)
    regions.push(nativeRegion(b, "trailer", end, b.length - end));
  return {
    format: "elf",
    bits,
    endian,
    architecture: u16(18),
    mappings,
    regions,
    entrypoint: resolveAddress(entry, mappings),
  };
}
export function parseMacho(b: Buffer): NativeLayout {
  extent(b, 0, 4, "Mach-O magic");
  const magic = b.readUInt32BE(0);
  check(
    ![0xcafebabe, 0xbebafeca, 0xcafebabf, 0xbfbafeca].includes(magic),
    "fat Mach-O unsupported; select and validate a slice externally",
  );
  const little = magic === 0xcefaedfe || magic === 0xcffaedfe,
    wide = magic === 0xfeedfacf || magic === 0xcffaedfe;
  check(
    [0xfeedface, 0xcefaedfe, 0xfeedfacf, 0xcffaedfe].includes(magic),
    "Mach-O magic unsupported",
  );
  const bits = wide ? 64 : 32,
    header = wide ? 32 : 28;
  extent(b, 0, header, "Mach-O header");
  const u32 = (p: number) => (little ? b.readUInt32LE(p) : b.readUInt32BE(p)),
    u64 = (p: number) => (little ? b.readBigUInt64LE(p) : b.readBigUInt64BE(p));
  check(u32(12) !== 1, "Mach-O MH_OBJECT section mapping unsupported");
  const count = u32(16),
    commandsSize = u32(20);
  check(count <= 512, "Mach-O load command count cap");
  extent(b, header, commandsSize, "Mach-O load commands");
  const mappings: NativeMapping[] = [],
    regions: Data[] = [nativeRegion(b, "headers", 0, header + commandsSize)];
  let p = header,
    end = header + commandsSize,
    entryOffset: number | undefined,
    mainCount = 0,
    sectionCount = 0;
  for (let i = 0; i < count; i++) {
    check(p + 8 <= header + commandsSize, "Mach-O truncated command header");
    const cmd = u32(p),
      size = u32(p + 4);
    check(
      size >= 8 &&
        size % (wide ? 8 : 4) === 0 &&
        size <= header + commandsSize - p,
      "Mach-O command size/alignment invalid",
    );
    if (cmd === 1 || cmd === 0x19) {
      const sw = cmd === 0x19;
      check(sw === wide, "Mach-O segment class mismatch");
      const base = sw ? 72 : 56,
        ss = sw ? 80 : 68;
      check(size >= base, "Mach-O segment command truncated");
      const n = u32(p + (sw ? 64 : 48));
      check(
        (sectionCount += n) <= 512 && size === base + n * ss,
        "Mach-O segment sections cap or command size mismatch",
      );
      const address = sw ? u64(p + 24) : BigInt(u32(p + 24)),
        mem = sw ? u64(p + 32) : BigInt(u32(p + 28)),
        offset = safe(
          sw ? u64(p + 40) : BigInt(u32(p + 32)),
          "Mach-O segment offset",
        ),
        fs = safe(
          sw ? u64(p + 48) : BigInt(u32(p + 36)),
          "Mach-O segment size",
        ),
        prot = u32(p + (sw ? 60 : 44)),
        segmentFlags = u32(p + (sw ? 68 : 52));
      // SG_HIGHVM places backed bytes above a low zero-filled prefix. This
      // adapter currently represents only ordinary low-to-high placement.
      check((segmentFlags & 1) === 0, "Mach-O SG_HIGHVM mapping unsupported");
      extent(b, offset, fs, "Mach-O segment");
      check(
        BigInt(fs) <= mem && address + mem <= 1n << BigInt(bits),
        "Mach-O segment virtual extent invalid",
      );
      mappings.push({
        index: i,
        fileOffset: offset,
        size: fs,
        address,
        memorySize: mem,
        executable: (prot & 4) !== 0,
      });
      regions.push(
        nativeRegion(b, "segment", offset, fs, {
          index: i,
          name: fixedName(b, p + 8, 16),
          virtualAddress: hex(address),
          memorySize: hex(mem),
          executable: (prot & 4) !== 0,
          fileBacked: fs > 0,
        }),
      );
      end = Math.max(end, offset + fs);
      const files: Array<{ offset: number; size: number }> = [];
      const virtualSections: Array<{ address: bigint; size: bigint }> = [];
      for (let j = 0; j < n; j++) {
        const q = p + base + j * ss,
          sa = sw ? u64(q + 32) : BigInt(u32(q + 32)),
          sz = safe(
            sw ? u64(q + 40) : BigInt(u32(q + 36)),
            "Mach-O section size",
          ),
          fo = u32(q + (sw ? 48 : 40)),
          flags = u32(q + (sw ? 64 : 56)),
          backed = ![1, 12, 18].includes(flags & 255);
        check(
          sa >= address && sa + BigInt(sz) <= address + mem,
          "Mach-O section outside segment virtual extent",
        );
        virtualSections.push({ address: sa, size: BigInt(sz) });
        if (backed) {
          extent(b, fo, sz, "Mach-O section");
          check(
            fo >= offset && fo + sz <= offset + fs,
            "Mach-O section outside segment file extent",
          );
          check(
            sa === address + BigInt(fo - offset),
            "Mach-O section contradicts segment file/VM translation",
          );
          files.push({ offset: fo, size: sz });
          regions.push(
            nativeRegion(b, "section", fo, sz, {
              index: j,
              name: fixedName(b, q, 16),
              fileBacked: true,
              virtualAddress: hex(sa),
              flags,
            }),
          );
        } else
          regions.push({
            kind: "section",
            index: j,
            name: fixedName(b, q, 16),
            declaredFileOffset: fo,
            size: sz,
            fileBacked: false,
            virtualAddress: hex(sa),
            flags,
            semanticAuthority: "unknown",
          });
      }
      disjoint(files, "Mach-O sections");
      const virtualOrder = virtualSections
        .filter((s) => s.size > 0n)
        .sort((a, b) =>
          a.address < b.address ? -1 : a.address > b.address ? 1 : 0,
        );
      for (let i = 1; i < virtualOrder.length; i++)
        check(
          virtualOrder[i - 1]!.address + virtualOrder[i - 1]!.size <=
            virtualOrder[i]!.address,
          "Mach-O section virtual ranges overlap",
        );
    } else if (cmd === 0x80000028) {
      check(
        size === 24 && ++mainCount === 1,
        "Mach-O LC_MAIN duplicate or invalid size",
      );
      entryOffset = safe(u64(p + 8), "Mach-O LC_MAIN entry offset");
    } else if (cmd === 0x1d) {
      check(size === 16, "Mach-O signature command invalid");
      const off = u32(p + 8),
        sz = u32(p + 12);
      regions.push(
        nativeRegion(b, "code-signature", off, sz, {
          signatureStatus: "unknown",
        }),
      );
      end = Math.max(end, off + sz);
    }
    p += size;
  }
  check(p === header + commandsSize, "Mach-O command count/size disagreement");
  validateMappings(mappings);
  let entrypoint: Data = {
    status: "unknown",
    reason: "LC_MAIN unavailable; LC_UNIXTHREAD not decoded",
  };
  if (entryOffset !== undefined) {
    const text = mappings.filter(
      (m) => m.fileOffset === 0 && m.size > 0 && m.executable,
    );
    check(
      text.length === 1 && entryOffset < text[0]!.size,
      "Mach-O LC_MAIN lacks unique executable text mapping",
    );
    entrypoint = resolveAddress(
      text[0]!.address + BigInt(entryOffset),
      mappings,
    );
  }
  if (end < b.length)
    regions.push(nativeRegion(b, "trailer", end, b.length - end));
  return {
    format: "macho",
    bits,
    endian: little ? "little" : "big",
    architecture: u32(4),
    mappings,
    regions,
    entrypoint,
  };
}

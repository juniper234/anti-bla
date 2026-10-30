import { createHash } from "node:crypto";
import {
  parsePe,
  parseElf,
  parseMacho,
  type NativeLayout,
  type NativeMapping,
  nativeRegion,
  NativeRefusal,
} from "./native/layouts.js";
export interface NativeOptions {
  offset?: number;
  limit?: number;
}
const sha = (b: Buffer) => createHash("sha256").update(b).digest("hex");
const LIMITS = {
  inputBytes: 64 * 1024 * 1024,
  layoutRecords: 512,
  defaultPage: 20,
  maxPage: 100,
  nameScanBytes: 4096,
  namePreviewBytes: 64,
  markerOccurrences: 128,
  regionHashBytes: 128 * 1024 * 1024,
  resultBytes: 65536,
};
function metadata(b: Buffer): {
  data: Record<string, unknown>;
  capped: boolean;
} {
  const patterns: Array<[string, Buffer]> = [
    ["bla-native-shield", Buffer.from("[BLA-NATIVE-SHIELD-V1]")],
    ["rustc-path", Buffer.from("/rustc/")],
    ["cargo-auditable-name", Buffer.from(".dep-v0")],
    ["go-buildinfo-magic", Buffer.from("\xff Go buildinf:", "latin1")],
    ["go-buildinfo-name", Buffer.from(".go.buildinfo")],
    ["go-framed-bait", Buffer.from("[BLA-GO-BUILDINFO]")],
    ["electron-fuse-sentinel", Buffer.from("dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX")],
    ["dart-snapshot-magic", Buffer.from([0xf5, 0xf5, 0xdc, 0xdc])],
    ["bun-trailer-sentinel", Buffer.from("\n---- Bun! ----\n")],
  ];
  let capped = false;
  const observations: Record<string, unknown>[] = [];
  for (const [marker, pattern] of patterns) {
    let from = 0,
      count = 0,
      complete = true;
    const offsets: number[] = [];
    while (from <= b.length - pattern.length) {
      const at = b.indexOf(pattern, from);
      if (at < 0) break;
      if (count === 128) {
        capped = true;
        complete = false;
        break;
      }
      count++;
      if (offsets.length < 20) offsets.push(at);
      from = at + pattern.length;
    }
    if (count)
      observations.push({
        marker,
        count,
        countComplete: complete,
        offsets,
        offsetsComplete: count <= 20,
        markerSha256: sha(pattern),
        semanticAuthority: "unknown",
      });
  }
  const trailer = Buffer.from("\n---- Bun! ----\n");
  let bun: Record<string, unknown> = {
    status: "unknown",
    reason:
      "no validated Bun graph; markers alone do not establish framework identity",
  };
  for (const suffix of [0, 8]) {
    const end = b.length - suffix,
      sentinel = end - trailer.length;
    if (sentinel >= 32 && b.subarray(sentinel, end).equals(trailer)) {
      const length =
        b.readBigUInt64LE(sentinel - 32) + BigInt(32 + trailer.length);
      if (length <= BigInt(end)) {
        const size = Number(length);
        bun = {
          status: "unknown",
          carrier: suffix ? "appended-trailer-sized" : "appended-trailer",
          fileOffset: end - size,
          size,
          sha256: sha(b.subarray(end - size, end)),
          graphSemantics: "not-parsed",
          toolchainIdentity: "unknown",
          sizeFooterValidated: false,
        };
        break;
      }
    }
  }
  return {
    capped,
    data: {
      semanticAuthority: "unknown",
      electronHardening: "unknown",
      observations,
      bun,
      warning:
        "Markers and section names are untrusted data, not behavior, genuine fuse identity, original metadata, or framework provenance.",
    },
  };
}
/** Pure immutable structural inspection. Never loads, executes or rewrites target bytes. */
export function inspectNative(
  bytes: Buffer,
  options: NativeOptions = {},
): Record<string, unknown> {
  const offset = options?.offset === undefined ? 0 : options.offset,
    limit = options?.limit === undefined ? 20 : options.limit;
  if (
    !Buffer.isBuffer(bytes) ||
    !options ||
    typeof options !== "object" ||
    Array.isArray(options) ||
    Object.keys(options).some((k) => !["offset", "limit"].includes(k)) ||
    !Number.isSafeInteger(offset) ||
    offset < 0 ||
    !Number.isSafeInteger(limit) ||
    limit < 1 ||
    limit > 100 ||
    !Number.isSafeInteger(offset + limit)
  )
    return {
      status: "error",
      reason: "invalid native buffer or paging options",
      limits: LIMITS,
    };
  if (bytes.length > LIMITS.inputBytes)
    return {
      status: "unknown",
      reason: "native input byte cap exceeded",
      sourceSha256: null,
      byteSize: bytes.length,
      limits: LIMITS,
    };
  const base = {
    sourceSha256: sha(bytes),
    byteSize: bytes.length,
    limits: LIMITS,
    immutableOriginal: true,
    untrustedArtifactData: true,
  };
  try {
    let layout: NativeLayout;
    if (bytes.length >= 2 && bytes[0] === 0x4d && bytes[1] === 0x5a)
      layout = parsePe(bytes);
    else if (
      bytes.length >= 4 &&
      bytes.subarray(0, 4).equals(Buffer.from([127, 69, 76, 70]))
    )
      layout = parseElf(bytes);
    else if (
      bytes.length >= 4 &&
      [
        0xfeedface, 0xcefaedfe, 0xfeedfacf, 0xcffaedfe, 0xcafebabe, 0xbebafeca,
        0xcafebabf, 0xbfbafeca,
      ].includes(bytes.readUInt32BE(0))
    )
      layout = parseMacho(bytes);
    else
      return {
        ...base,
        status: "unknown",
        reason: "unsupported or truncated native magic",
      };
    if (layout.regions.length > 1032)
      throw new NativeRefusal("combined native region cap exceeded");
    const markers = metadata(bytes),
      executable = layout.mappings
        .filter((m) => m.executable && m.size > 0)
        .map((m: NativeMapping) =>
          nativeRegion(bytes, "executable-mapping", m.fileOffset, m.size, {
            mappingIndex: m.index,
            virtualAddress: `0x${m.address.toString(16)}`,
            memorySize: `0x${m.memorySize.toString(16)}`,
            reachability: "not-established",
          }),
        );
    let hashedBytes = 0;
    const hashPage = (items: Record<string, unknown>[]) =>
      items.map((r) => {
        if (typeof r.fileOffset !== "number" || typeof r.size !== "number")
          return r;
        hashedBytes += r.size;
        if (hashedBytes > LIMITS.regionHashBytes)
          throw new NativeRefusal("native region hash byte cap reached");
        return {
          ...r,
          sha256: sha(bytes.subarray(r.fileOffset, r.fileOffset + r.size)),
        };
      });
    const result = {
      ...base,
      status: markers.capped ? "unknown" : "ok",
      ...(markers.capped
        ? { reason: "metadata marker occurrence cap reached" }
        : {}),
      format: layout.format,
      bits: layout.bits,
      endian: layout.endian,
      architecture: layout.architecture,
      entrypoint: layout.entrypoint,
      signatureStatus: "unknown",
      regions: hashPage(layout.regions.slice(offset, offset + limit)),
      pagination: {
        offset,
        limit,
        total: layout.regions.length,
        returned: layout.regions.slice(offset, offset + limit).length,
        complete: offset === 0 && layout.regions.length <= limit,
      },
      executableRanges: hashPage(executable.slice(offset, offset + limit)),
      executablePagination: {
        offset,
        limit,
        total: executable.length,
        complete: offset === 0 && executable.length <= limit,
      },
      metadata: markers.data,
      limitations: [
        "Structural validation is not loader equivalence, code reachability, signature validity or source recovery.",
        "Executable range hashes establish byte identity only.",
        "Framework metadata may be overwritten by BLA; original values are not reconstructed.",
        "LC_UNIXTHREAD, fat Mach-O, MH_OBJECT and SG_HIGHVM are unsupported; ELF extended counts are unsupported; PE page-size admission is limited to x86/x64.",
      ],
    };
    if (Buffer.byteLength(JSON.stringify(result)) > LIMITS.resultBytes)
      throw new NativeRefusal(
        "native result byte cap exceeded; request a smaller page",
      );
    return result;
  } catch (error) {
    return {
      ...base,
      status: "unknown",
      reason:
        error instanceof NativeRefusal
          ? error.message
          : "native parser refused unexpected input",
      regions: [],
      executableRanges: [],
    };
  }
}

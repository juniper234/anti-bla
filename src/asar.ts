import { createHash } from 'node:crypto';

export type AsarOptions = { maxHeaderBytes?: number; maxEntries?: number };
export type AsarInspectOptions = AsarOptions & { offset?: number; limit?: number };
export type AsarSelector = { path: string; offset?: number; length?: number };
type JsonObject = Record<string, unknown>;
type Entry = { path: string; kind: 'file' | 'directory' | 'link' | 'unpacked'; size?: number; start?: number; integrityPresent: boolean };
type Parsed = { entries: Entry[]; headerBytes: number; jsonBytes: number; dataOffset: number; unsupported: boolean };
type Result = { schema: string; operation: string; status: 'ok' | 'unknown' | 'error'; behavioralEquivalence: 'unknown'; [key: string]: unknown };

const DEFAULT_HEADER = 32 * 1024 * 1024;
const HARD_HEADER = 64 * 1024 * 1024;
const EXPANDED_PATH_BUDGET = 64 * 1024 * 1024;
const LIMITATIONS = [
  'Read-only structural inspection and original byte views do not establish executable equivalence or identify decoys.',
  'Declared ASAR integrity, Electron signatures, fuses and runtime acceptance were not verified.',
  'Links are never followed; external unpacked content is unsupported.',
];
class AsarFailure extends Error {
  constructor(readonly code: string, readonly status: 'error' | 'unknown' = 'error') { super(code); }
}
const fail = (code: string, status: 'error' | 'unknown' = 'error'): never => { throw new AsarFailure(code, status); };
const digest = (bytes: Buffer): string => createHash('sha256').update(bytes).digest('hex');
const object = (value: unknown): value is JsonObject => typeof value === 'object' && value !== null && !Array.isArray(value);
const own = (value: JsonObject, key: string): boolean => Object.hasOwn(value, key);
function integer(value: unknown, minimum: number, maximum: number, code: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < minimum || value > maximum) return fail(code);
  return value;
}
function options(value: AsarOptions | AsarInspectOptions, listing: boolean): { maxHeaderBytes: number; maxEntries: number; offset: number; limit: number } {
  if (!object(value) || Object.keys(value).some(key => !['maxHeaderBytes', 'maxEntries', ...(listing ? ['offset', 'limit'] : [])].includes(key))) return fail('ASAR_INVALID_OPTIONS');
  const view = value as AsarInspectOptions;
  return {
    maxHeaderBytes: integer(value.maxHeaderBytes ?? DEFAULT_HEADER, 1, HARD_HEADER, 'ASAR_INVALID_OPTIONS'),
    maxEntries: integer(value.maxEntries ?? 10_000, 1, 50_000, 'ASAR_INVALID_OPTIONS'),
    offset: integer(view.offset ?? 0, 0, Number.MAX_SAFE_INTEGER, 'ASAR_INVALID_OPTIONS'),
    limit: integer(view.limit ?? 20, 1, 100, 'ASAR_INVALID_OPTIONS'),
  };
}
function safeSegment(value: string): boolean {
  return value.length > 0 && value !== '.' && value !== '..'
    && !/[\/\\:\u0000-\u001f\u007f\uD800-\uDFFF]/u.test(value)
    && !/[. ]$/u.test(value)
    && !/^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)/iu.test(value);
}
function safePath(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.split('/').length <= 64 && value.split('/').every(safeSegment);
}

/** Preflight native JSON decoding: bound nesting and refuse duplicate decoded
 * object keys (including escaped aliases), rather than silently taking the last.
 * JSON.parse subsequently validates the complete grammar. No target code runs. */
function preflightJson(json: string): void {
  const frames: { object: boolean; key: boolean; keys: Set<string> }[] = [];
  for (let i = 0; i < json.length; i++) {
    const char = json[i];
    if (char === '"') {
      const start = i++;
      for (; i < json.length; i++) {
        if (json[i] === '\\') { i++; continue; }
        if (json[i] === '"') break;
      }
      const frame = frames.at(-1);
      if (frame?.object && frame.key) {
        let key: unknown;
        try { key = JSON.parse(json.slice(start, i + 1)); } catch { return fail('ASAR_INVALID_JSON'); }
        if (typeof key !== 'string') return fail('ASAR_INVALID_JSON');
        if (frame.keys.has(key)) return fail('ASAR_DUPLICATE_KEY');
        frame.keys.add(key); frame.key = false;
      }
    } else if (char === '{' || char === '[') {
      frames.push({ object: char === '{', key: char === '{', keys: new Set() });
      if (frames.length > 136) return fail('ASAR_DEPTH_LIMIT', 'unknown');
    } else if (char === '}' || char === ']') {
      frames.pop();
    } else if (char === ',') {
      const frame = frames.at(-1); if (frame?.object) frame.key = true;
    }
  }
}

function parse(bytes: Buffer, limits: { maxHeaderBytes: number; maxEntries: number }): Parsed {
  if (!Buffer.isBuffer(bytes)) return fail('ASAR_INVALID_BUFFER');
  if (bytes.length < 16) return fail('ASAR_TRUNCATED_HEADER');
  const headerBytes = bytes.readUInt32LE(4), payloadBytes = bytes.readUInt32LE(8), jsonBytes = bytes.readUInt32LE(12);
  if (bytes.readUInt32LE(0) !== 4 || headerBytes < 8 || headerBytes % 4 !== 0
      || payloadBytes !== headerBytes - 4 || jsonBytes === 0
      || Math.ceil(jsonBytes / 4) * 4 !== payloadBytes - 4) return fail('ASAR_INVALID_PICKLE');
  const dataOffset = 8 + headerBytes;
  if (dataOffset > bytes.length || 16 + jsonBytes > dataOffset) return fail('ASAR_TRUNCATED_HEADER');
  if (headerBytes > limits.maxHeaderBytes) return fail('ASAR_HEADER_LIMIT', 'unknown');
  // Chromium Pickle's string padding carries no entry bytes.
  for (let i = 16 + jsonBytes; i < dataOffset; i++) if (bytes[i] !== 0) return fail('ASAR_INVALID_PICKLE_PADDING');
  let json: string;
  try { json = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes.subarray(16, 16 + jsonBytes)); }
  catch { return fail('ASAR_INVALID_UTF8'); }
  preflightJson(json);
  let root: unknown;
  try { root = JSON.parse(json); } catch { return fail('ASAR_INVALID_JSON'); }
  if (!object(root) || !object(root.files) || Object.keys(root).some(key => key !== 'files')) return fail('ASAR_INVALID_ROOT');
  const entries: Entry[] = [];
  const ranges: { start: number; end: number }[] = [];
  let unsupported = false, retainedPathBytes = 0;
  const frame = (files: JsonObject, parent: string, depth: number) => ({ files, names: Object.keys(files), index: 0, parent, depth, aliases: new Set<string>() });
  const pending = [frame(root.files, '', 1)];
  while (pending.length > 0) {
    const current = pending.at(-1)!;
    if (current.index >= current.names.length) { pending.pop(); continue; }
    if (current.depth > 64) return fail('ASAR_DEPTH_LIMIT', 'unknown');
    if (entries.length >= limits.maxEntries) return fail('ASAR_ENTRY_LIMIT', 'unknown');
    const name = current.names[current.index++]!;
    if (!safeSegment(name)) return fail('ASAR_UNSAFE_PATH');
    const alias = name.normalize('NFC').toLowerCase();
    if (current.aliases.has(alias)) return fail('ASAR_AMBIGUOUS_PATH', 'unknown');
    current.aliases.add(alias);
    const pathUnits = current.parent.length + (current.parent.length ? 1 : 0) + name.length;
    retainedPathBytes += pathUnits * 2 + 256;
    if (retainedPathBytes > EXPANDED_PATH_BUDGET) return fail('ASAR_EXPANDED_PATH_LIMIT', 'unknown');
    const path = current.parent ? `${current.parent}/${name}` : name;
    const node = current.files[name];
    if (!object(node)) return fail('ASAR_INVALID_NODE');
    if (Object.keys(node).some(key => !['files', 'link', 'size', 'offset', 'unpacked', 'executable', 'integrity'].includes(key))) return fail('ASAR_INVALID_NODE');
    if (own(node, 'files')) {
      if (!object(node.files) || Object.keys(node).some(key => key !== 'files')) return fail('ASAR_INVALID_NODE');
      entries.push({ path, kind: 'directory', integrityPresent: false });
      pending.push(frame(node.files, path, current.depth + 1));
      continue;
    }
    if (own(node, 'link')) {
      if (Object.keys(node).length !== 1 || !safePath(node.link)) return fail('ASAR_UNSAFE_LINK');
      entries.push({ path, kind: 'link', integrityPresent: false }); unsupported = true; continue;
    }
    if ((own(node, 'executable') && typeof node.executable !== 'boolean')
        || (own(node, 'unpacked') && typeof node.unpacked !== 'boolean')
        || (own(node, 'integrity') && !object(node.integrity))) return fail('ASAR_INVALID_NODE');
    const size = integer(node.size, 0, Number.MAX_SAFE_INTEGER, 'ASAR_INVALID_SIZE');
    if (node.unpacked === true) {
      if (own(node, 'offset')) return fail('ASAR_INVALID_NODE');
      entries.push({ path, kind: 'unpacked', size, integrityPresent: own(node, 'integrity') }); unsupported = true; continue;
    }
    if (typeof node.offset !== 'string' || !/^(?:0|[1-9][0-9]*)$/u.test(node.offset)) return fail('ASAR_INVALID_OFFSET');
    const offset = integer(Number(node.offset), 0, Number.MAX_SAFE_INTEGER, 'ASAR_INVALID_OFFSET');
    const start = dataOffset + offset, end = start + size;
    if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start > bytes.length || end > bytes.length) return fail('ASAR_ENTRY_OUT_OF_BOUNDS');
    if (size > 0) ranges.push({ start, end });
    entries.push({ path, kind: 'file', size, start, integrityPresent: own(node, 'integrity') });
  }
  ranges.sort((a, b) => a.start - b.start);
  for (let i = 1; i < ranges.length; i++) if (ranges[i]!.start < ranges[i - 1]!.end) return fail('ASAR_OVERLAPPING_RANGES');
  return { entries, headerBytes, jsonBytes, dataOffset, unsupported };
}
function pathView(path: string): object {
  const bytes = Buffer.from(path, 'utf8');
  const basic = { length: path.length, byteLength: bytes.length, sha256: digest(bytes) };
  if (bytes.length <= 256) return { ...basic, text: path, truncated: false };
  let preview = '', count = 0;
  for (const point of path) { if (count++ === 64) break; preview += point; }
  return { ...basic, preview, truncated: true };
}
function entryView(entry: Entry): object {
  return { path: pathView(entry.path), kind: entry.kind,
    ...(entry.size === undefined ? {} : { size: entry.size }),
    ...(entry.start === undefined ? {} : { archiveRange: { offset: entry.start, length: entry.size } }),
    integrity: { declared: entry.integrityPresent, verification: 'not-verified' },
  };
}
function base(bytes: Buffer, operation: string, parsed: Parsed): Result {
  return { schema: 'anti-bla.asar/1', operation, status: 'ok', behavioralEquivalence: 'unknown',
    archive: { byteLength: bytes.length, sha256: digest(bytes) },
    header: { byteOffset: 8, byteLength: parsed.headerBytes, jsonByteOffset: 16, jsonByteLength: parsed.jsonBytes,
      dataByteOffset: parsed.dataOffset, sha256: digest(bytes.subarray(8, parsed.dataOffset)) },
    limitations: LIMITATIONS,
  };
}
function failed(operation: string, error: unknown): Result {
  return { schema: 'anti-bla.asar/1', operation, status: error instanceof AsarFailure ? error.status : 'error',
    reason: { code: error instanceof AsarFailure ? error.code : 'ASAR_INTERNAL_ERROR' }, behavioralEquivalence: 'unknown', limitations: LIMITATIONS };
}

/** Bounded, read-only structural listing. Output paths are untrusted metadata. */
export function inspectAsar(bytes: Buffer, requested: AsarInspectOptions = {}): Result {
  const operation = 'inspect_asar';
  try {
    const limits = options(requested, true), parsed = parse(bytes, limits);
    const selected = parsed.entries.slice(limits.offset, limits.offset + limits.limit);
    const counts = { file: 0, directory: 0, link: 0, unpacked: 0 };
    for (const entry of parsed.entries) counts[entry.kind]++;
    return { ...base(bytes, operation, parsed), status: parsed.unsupported ? 'unknown' : 'ok',
      ...(parsed.unsupported ? { reason: { code: 'ASAR_EXTERNAL_CONTENT_UNSUPPORTED' } } : {}),
      totalEntries: parsed.entries.length, counts,
      page: { offset: limits.offset, limit: limits.limit, returned: selected.length,
        nextOffset: limits.offset + selected.length < parsed.entries.length ? limits.offset + selected.length : null },
      entries: selected.map(entryView), listingOrder: 'header-depth-first',
    };
  } catch (error) { return failed(operation, error); }
}

/** Original packed byte view only: never extracts, follows a link, or executes. */
export function readAsarEntry(bytes: Buffer, selector: AsarSelector, requested: AsarOptions = {}): Result {
  const operation = 'read_asar_entry';
  try {
    if (!object(selector) || Object.keys(selector).some(key => !['path', 'offset', 'length'].includes(key)) || !safePath(selector.path)) return fail('ASAR_INVALID_SELECTOR');
    const offset = integer(selector.offset ?? 0, 0, Number.MAX_SAFE_INTEGER, 'ASAR_INVALID_SELECTOR');
    const length = integer(selector.length ?? 1024, 0, 4096, 'ASAR_INVALID_SELECTOR');
    const parsed = parse(bytes, options(requested, false));
    const entry = parsed.entries.find(candidate => candidate.path === selector.path);
    if (!entry) return fail('ASAR_ENTRY_NOT_FOUND');
    if (entry.kind !== 'file') return fail(entry.kind === 'link' ? 'ASAR_LINK_UNSUPPORTED'
      : entry.kind === 'unpacked' ? 'ASAR_UNPACKED_UNSUPPORTED' : 'ASAR_DIRECTORY_UNSUPPORTED', 'unknown');
    if (offset > entry.size!) return fail('ASAR_VIEW_OUT_OF_BOUNDS');
    const actualLength = Math.min(length, entry.size! - offset), archiveOffset = entry.start! + offset;
    const view = bytes.subarray(archiveOffset, archiveOffset + actualLength);
    return { ...base(bytes, operation, parsed), entry: entryView(entry), archiveScope: 'packed-entry-only',
      archiveHasUnsupportedContent: parsed.unsupported,
      view: { entryOffset: offset, archiveOffset, length: actualLength, sha256: digest(view), base64: view.toString('base64'),
        truncated: offset + actualLength < entry.size! },
    };
  } catch (error) { return failed(operation, error); }
}

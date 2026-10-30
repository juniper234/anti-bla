# Bounded ASAR inspection and byte views

`src/asar.ts` exports pure, synchronous buffer adapters. They neither open files nor extract, rewrite, import, or execute archive content.

```ts
inspectAsar(bytes: Buffer, options?: {
  maxHeaderBytes?: number; maxEntries?: number; offset?: number; limit?: number;
}): object

readAsarEntry(bytes: Buffer, selector: {
  path: string; offset?: number; length?: number;
}, options?: { maxHeaderBytes?: number; maxEntries?: number }): object
```

Defaults and hard maxima:

| Admission/view | Default | Maximum |
| --- | ---: | ---: |
| Header pickle bytes, excluding first 8 archive bytes | 32 MiB | 64 MiB |
| Entries, including directories/links/unpacked metadata | 10,000 | 50,000 |
| Listing page | 20 | 100 |
| Entry byte view | 1,024 | 4,096 |
| Path depth | 64 segments | 64 segments |
| Expanded path accounting | 64 MiB | 64 MiB |

Expanded paths charge two bytes per UTF-16 code unit plus 256 bytes per entry. This is an admission accounting rule, not a measurement of engine heap usage. Header parsing and structural validation cover the whole admitted header before any page or member is returned; selecting one member does not avoid that work. Callers must impose their own archive input, heap, deadline and final JSON output limits, as the service does.

Results use `schema: "anti-bla.asar/1"`, `status: "ok" | "unknown" | "error"`, and `behavioralEquivalence: "unknown"`. `ok` means the returned structure or packed byte view was validated within these limits. It is never a bypass, semantic recovery, decoy classification, integrity validation, or Electron acceptance claim.

`inspectAsar` returns original archive length/SHA-256, header coordinates/SHA-256, entry counts and a header-order depth-first page. The header range begins at byte 8, JSON begins at byte 16, and packed data begins at `8 + header.byteLength`. Directory names count as entries. `page.nextOffset` is null after the last entry. A valid offset beyond the end produces an empty page.

Every listed path has an exact UTF-8 SHA-256, `length` in UTF-16 code units and `byteLength` in UTF-8 bytes. Paths up to 256 UTF-8 bytes have `text`; longer paths have a preview of at most 64 Unicode code points and `truncated: true`. A long path is metadata, not evidence that the entry is a decoy. To read such an entry, supply its exact original path; hashes are identifiers, not substitute selectors.

`readAsarEntry` selects an exact slash-separated relative path without normalization. It returns the entry's original `archiveRange` and a `view` with `entryOffset`, absolute `archiveOffset`, returned byte length, SHA-256 and base64. SHA-256 covers the returned view; it is not a full entry digest when the view is partial. The read clips at entry end, accepts a zero-byte view at the end, and refuses offsets beyond the entry. `truncated` indicates that bytes remain after the view. Binary and zero-byte members work without JavaScript parsing.

Malformed pickle lengths, alignment/padding, invalid UTF-8/JSON, duplicate decoded JSON keys, unsupported node shapes, unsafe numeric values, out-of-bounds extents and overlapping nonempty ranges return `error`. Resource limits and case/NFC path collisions return `unknown`. The portable path policy refuses empty/dot/parent segments, slash or backslash inside names, colon/drive/UNC forms, control/NUL/lone-surrogate characters, trailing dot/space and Windows reserved device names. Valid UTF-8 names otherwise remain exact. This conservative policy may refuse a name representable on only one host platform.

Link targets must be safe relative paths. Links are never followed. A structurally valid archive containing a link or unpacked member has an `unknown` inspection with a bounded listing. Reading that unsupported member returns `unknown`; reading an independently validated packed member can return `ok` with `archiveScope: "packed-entry-only"` and `archiveHasUnsupportedContent: true`. External `.asar.unpacked` content is never read. Directory selectors are also unsupported for byte views.

ASAR integrity declarations are only marked present/unverified. External signatures, block hashes, genuine Electron fuse hardening, runtime behavior, and the truth of embedded text remain unverified.

# Qualification and reproduction

Run using the isolated supported runtime, after building the project:

```powershell
& '.runtime/node-v24.22.1-win-x64/node.exe' node_modules/typescript/bin/tsc -p tsconfig.json
& '.runtime/node-v24.22.1-win-x64/node.exe' --test test/asar.test.mjs
& '.runtime/node-v24.22.1-win-x64/node.exe' scripts/qualify-asar.mjs
```

The runner accepts `--seeds=seed1,seed2,seed3` for exact reproduction. It emits controlled fixtures beneath `scratch/asar`, deletes only its own case directories, and preserves timestamped JSON reports and raw command/exit/stdout/stderr logs under `reports/C4*`. It sets TEMP/TMP only in its own process for REA snapshot files. No targets or target-supplied commands execute.

The measured run `reports/C4-qualification-20261030015707496.json` uses BLA `b2d6436`/1.5.1 and REA `317bf3f`/6.8.0 on Node v24.22.1. Three independent seeds each exercise an independently framed clean archive, actual pinned BLA bankrupt header amplification, equal-header-length benign catalog assets, actual full `protectTarget`, and a corrupted pickle. The actual REA `AsarArtifactReader` inventories and streams selected members under default, environment 32/256 MiB, and runtime 256 MiB admissions. Runtime settings use REA's real `AnalysisSettings.update`; values above 256 MiB are refused.

All 15 case expectations were observed. Amplifier and benign headers were exactly 17,442,012 bytes; full-protector headers were 17,443,716 bytes. REA's default 16 MiB cap refused all nine large-header cases. `REA_ASAR_MAX_HEADER_BYTES=33554432`, `268435456`, and runtime `asar.max_header_bytes=268435456` admitted them and REA streamed exact packed package/main bytes. This establishes a configurable admission obstruction and a separately verified static byte task, not complete analysis recovery.

Anti-BLA recovered both original members after amplifier-only protection, and the unchanged original package manifest after full protection. Full protection changed `main.js`; its original source and behavioral equivalence remain UNKNOWN. Its bounded view still matched the exact corresponding protected archive bytes. Corruptions were refused, and benign long paths received the same structural treatment.

Fresh independent review and service/MCP integration measurements are separate root tasks. The qualification child's recorded peak RSS includes fixture generation and all four REA runs and must not be attributed to the adapter alone.

Public evidence availability and reproduction: [research notes](RESEARCH.md#local-evidence). Timestamped raw-report names in this guide refer to retained local records.

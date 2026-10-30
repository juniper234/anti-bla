# Native/framework companion (C5)

`inspectNative(bytes: Buffer, options?: { offset?: number; limit?: number }): object` is exported by `src/native.ts`. It reads immutable original bytes only. `offset` is the **record page index**, not a source-byte offset. Default page size is 20; maximum 100. Invalid arguments return `status: error`; unsupported, malformed, ambiguous or capped observations return `status: unknown` with a reason. An admitted structure returns `status: ok`, which does not mean semantic recovery or acceptance PASS.

Every admitted input has `sourceSha256` and `byteSize`. Paged `regions` and `executableRanges` identify original `fileOffset`, `size` and SHA-256. Virtual addresses and memory extents are hex strings. `entrypoint` maps a declared entry only when exactly one file-backed executable mapping contains it. Section names are bounded previews plus exact byte hashes/coordinates. NOBITS/zero-fill records have `fileBacked: false` and a declared offset, never a fabricated file hash. Separate pagination totals prevent a short page from implying complete coverage.

Supported structural fields:

| Layout | Admission and boundaries |
| --- | --- |
| PE32/PE32+ | DOS/PE/COFF/optional headers, directory counts and backed RVA extents, loader alignments, section raw/virtual extents and executable flags. Page-size admission is limited to x86/x64; low-alignment file-backed sections must have raw offset equal to RVA. Other machines return UNKNOWN. Security directory is a file offset, separated from trailers. WIN_CERTIFICATE record extents are bounded; signature validity stays unknown. |
| ELF32/ELF64, both byte orders | Header/version, fixed-size program/section tables, PT_LOAD executable mappings and file/memory size/alignment checks; bounded section names. SHF_ALLOC virtual extents are width checked even for NOBITS, without a manufactured file hash. The half-open end may equal the address-space ceiling. Extended counts are unsupported. |
| Thin Mach-O32/64, both byte orders | Load-command count/size/alignment, segment/section extents, section virtual disjointness and file-to-VM translation consistency, executable protection and LC_MAIN mapping, code-signature byte extent. SG_HIGHVM and MH_OBJECT are explicitly unsupported. LC_UNIXTHREAD and other command payload semantics are not decoded. Fat/universal carriers return precise unsupported status. |

Mapped file or virtual overlaps are refused conservatively. Valid formats outside these rules can therefore return UNKNOWN. This is a bounded view of admitted fields, not a complete operating-system loader or a guarantee that every unused field is valid.

Limits are returned in each result: 64MiB input; 512 records per table; 4096 bytes per name scan and 64 bytes per name preview; 128 occurrences per marker; 128MiB cumulative hash work on emitted regions; 64KiB result JSON. Inputs exceeding 64MiB are refused **before hashing**, with `sourceSha256: null`; other refusal results retain the input digest. Paging does not relax structural validation. Runtime timeout/cancellation/worker isolation belongs to the shared service; this module spawns no processes.

`metadata` only reports bounded untrusted marker observations, never instructions or authoritative framework facts. Electron sentinel presence does not identify a genuine fuse wire or establish hardening. Bun EOF suffix observations do not validate its graph, footer semantics or toolchain identity. No target import, eval, execution, patching, signature verification, symbol restoration or original overwritten metadata recovery occurs.

## Measured observations

Source pins are BLA 1.5.1 `b2d643600774d62e562081129e55b13b0d9e8a80` and REA 6.8.0 `317bf3fe235e655b2d752d3be261cc0da7d00f2b`. Actual BLA `protectNativeBinary`, intensity `maximum`, was called on independently owned fixtures. Actual REA used its **source wrapper**, supported local Node 24.22.1, and Ghidra 12.1.4 for PE code. Each row below has three fixture/seed runs, with hashes and raw provider results retained in `reports/C5-native.json` and `scratch/native/runs`.

| Controlled task | Observation | Remaining limit |
| --- | --- | --- |
| Hand-authored x64 PE `score(value)` variants value*3+7, value*5+11, value*7+13 | Clean and BLA-protected direct REA/Ghidra return each function body. Anti's original file coordinate `0x200` handed to REA also recovers it in 3/3. Executable mapping hashes are identical. | Baseline already succeeds: this demonstrates bounded static recovery beyond bait, not an incremental bypass. These are small owned PE carriers, not genuine framework applications. |
| Same PE Electron metadata probes | Clean control lacks a genuine fuse claim; BLA-protected calls hit REA's 32-sentinel resource guard. | This metadata rejection does not prevent successful code decompilation and does not establish genuine Electron hardening. |
| Actual Go 1.27.0 Linux ELF builds | All 3 stay structurally admitted with byte-identical executable mappings. Actual BLA overwrites mapped `.go.buildinfo`; clean REA reads Go 1.27.0, protected REA rejects the declared build-info string over1MiB. | Original overwritten build metadata is **not recovered**. Windows native REA P0 does not admit ELF business-function decompilation. |
| Actual Rust 1.91.0 Linux ELF builds | All 3 retain original prefixes and executable hashes. Source REA's mapped Rust reader still observes the same original rustc path hash before/after trailer bait, with absent `.dep-v0`. | No cargo-auditable dependency recovery or ELF business-function recovery claimed. The unaffected baseline is not a bypass. |
| Actual Bun 1.3.9 Windows `.bun` carrier | All 3 generated executables are 114,090,072 bytes. Actual BLA appends bait while preserving the original prefix. Source REA locates each entry module's original offset/length; reading those bytes recovers the expected stored `score` source, identically before/after protection. | Anti refuses these artifacts at its 64MiB input cap. REA-only stored-source evidence is recorded separately from Anti admission. |
| Actual Bun 1.3.9 Linux sized EOF carrier | All 3 are `appended-trailer-sized`; actual BLA returns each entire artifact byte-exact. Source REA locates each preserved entry module and its `score` source bytes. | Artifacts are 102,367,881–102,367,882 bytes, so Anti remains UNKNOWN. This is a pass-through red line, not defeated protection. |
| Flutter, actual Electron app | No genuine artifact/toolchain qualification completed. | UNKNOWN. Synthetic pool/fuse/header carriers do not stand in for real applications or genuine fuse authority. |

No generated target was executed, on host or in a container. Trusted Rust/Bun Linux compilers ran in own containers with network none, read-only root, nonroot 65534, dropped capabilities, no-new-privileges, bounded pids/CPU/memory and own mounts. Tool archives were verified against published SHA-256; exact downloads/versions are in `reports/C5-native-tools.json`. Provider wall times are monotonic measurements; provider CPU/peak memory are null because unmeasured.

Initial decimal REA coordinates were correctly rejected; corrected calls use hexadecimal. The first pseudocode classifier incorrectly rejected valid hex constants and was corrected by parsing numeric literals without eval. Initial emitter timing spanned later provider calls; that measurement is explicitly rejected/null. All rejected records remain in `reports/C5-native-attempt1.json` and raw logs. Node-spawned Docker calls lacked pipe access; direct PowerShell compiler calls succeeded with recorded commands. No permissions were changed.

## Verification and continuation

The original `node --test test/native-layout.test.mjs` suite has 14 cases. Fix round 1 adds 27 targeted admission tests: the combined native regression passes 41/41, and `npm test` passes 164/164. Timestamped commands, RED→GREEN logs, current source identities and the current artifact/hash replay are recorded in `reports/C5-FIX-ROUND1.md`. Older alias reports remain historical evidence, including the earlier shared integration RED and original 9-row layout replay; they are not overwritten by the fix round.

Core reproducible qualification: dot-source `.runtime/providers/environment.ps1`, then run `.runtime/node-v24.22.1-win-x64/node.exe scripts/qualify-native.mjs`. It uses the tracked independent literal fixture source `test/helpers/native-fixtures.mjs` and emits only owned controlled artifacts and raw static-analysis results. Every invocation has a timestamped `scratch/native/runs/<runId>` directory and `reports/C5-native-core-<runId>.json`, preserving existing evidence. The original scratch helper is retained for earlier source-hash evidence references; the tracked copy has only formatting changes. Additional exact fixture/build/evidence scripts remain in `scratch/native/further.mjs`, `framework-controls.mjs`, `finalize.mjs`, plus recorded container build commands; the supplemental scripts are experiment records, not universal rerun automation.

Verdict: **CONDITIONAL, audit_source:self**. This white-box fixture qualification has no blind damage reviewer and cannot be called C5 PASS. Next actions are supported Linux/macOS REA native code qualification on the owned Go/Rust ELF functions, a genuine Flutter fixture, real Electron provenance/fuse context, and independent artifact-only review. Byte-identical executable ranges establish preserved bytes, not complete executable equivalence, signatures or runtime behavior.




Public evidence availability and reproduction: [research notes](RESEARCH.md#local-evidence). Timestamped raw-report names in this guide refer to retained local records.

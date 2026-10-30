# Streaming Formats Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Inspect exact selected structures/bytes in genuine large artifacts without whole-file Buffer allocation or weakened format validation.

**Architecture:** Add a metered asynchronous ArtifactSource and port format I/O behind the explicit streaming-v1 profile. Preserve existing Buffer exports/defaults; reuse their reviewed semantic/admission rules and compare both implementations on small fixtures.

**Tech Stack:** Node file handles/crypto, bigint arithmetic, bounded incremental parsers, existing TypeScript/node:test and optional independent canonical-reader research comparisons.

**Spec:** [Engineering design](../../specs/2026-10-30-comprehensive-recovery-design.md), sections 5-6 and 9. Read `src/artifacts.ts`, `src/asar.ts`, `src/native.ts`, `src/native/layouts.ts`, `src/formats/common.ts`, `src/formats/model.ts` and existing regression controls.

## Global Constraints

- Keep Node.js `>=24.16.0` for the existing product. Initial REA integration uses a separately admitted Node.js `24.22.1` runtime.
- Existing `anti-bla.result/1`, `status: ok|unknown|error`, CLI exits 0/3/2, and `behavioralEquivalence: unknown` remain compatible.
- Default product operations parse inert bytes only and create no files.
- streaming-v1: 2 GiB file admission, 512 MiB cumulative physical reads, 256 MiB hash work also charged to reads, 64 KiB chunks, 4 MiB live byte buffers, 50,000 metadata entries, 32 MiB ASAR header; hard ceilings are in the design.
- Missing prerequisites and excluded research tests never count as passes. No AI/co-author attribution in commits or release text.

## Review Focus

1. Offset/size multiplication rounds through Number or wraps at 32 bits: check bigint extents before conversion/allocation (S0/S1/S4).
2. Range digest is labelled as a complete original hash or file changes mid-scan: unknown identity, no full-artifact handoff (S0/S5).
3. Selected ASAR member looks valid while another header record is ambiguous/overlapping: retain full structural validation (S2).
4. Bun sidecar/trailer/name bait substitutes for the actual executable-contained graph: exact carrier/occurrence identity (S3).
5. Bplist prefix or damaged GGUF candidate is reported as a valid repaired original: conditional separate result only (S4).

## Task S0: Metered range source, hashing and stability

**Files:** Create `src/io/source.ts`, `local-source.ts`, `buffer-source.ts`, `member-source.ts`, `budget.ts`, `cursor.ts`, `policy.ts`; reuse path admission in existing `src/artifacts.ts`; create `test/artifact-source.test.mjs`, `test/artifact-source-budget.test.mjs`, `test/artifact-source-races.test.mjs`, `test/member-source.test.mjs`.

**Consumes:** F0 shared ByteRange/SourceIdentity, policy and OperationContext. **Produces:** `ArtifactSource {byteLength:bigint, readExact(range:InternalRange,purpose):Promise<Buffer>, chunks(range,purpose):AsyncIterable<Buffer>, hashRange(range):Promise<RangeDigest>, finish():Promise<SourceIdentity>, close():Promise<void>}`. Define InternalRange as bigint offset/length; purpose is metadata/content/hash. `openArtifactSource(path, context): Promise<ArtifactSource>` pins one authorized descriptor; `BufferSource` gives identical logical accounting for parser tests.

RangeDigest is the design's RangeEvidence with exact observation/coordinate/digest scope. Add `openMemberSource(parent, descriptor, context): Promise<MemberSource>`; MemberSource carries complete child-byte identity plus the parent/member-occurrence relationship. Initial product member sources support stored ranges only. Compressed/unknown encoding returns unsupported_member_encoding, never an unmetered provider fallback or fabricated affine mapping. Before any later codec is admitted, its owning task must implement reserve-before-expansion, actual output/retained-byte counters, cancellation, checksum/declared-size completion and decoded-coordinate provenance, with decompression-bomb controls. When REA itself decompresses, record its separately reviewed provider limits/measurements; Anti's physical-read counters do not include opaque provider work.

Reserve before I/O/allocation; charge duplicate reads, hashing reads, metadata, decoded expansion, retained indexes and parser steps. Add read-call cap 100,000 default/200,000 hard and index-accounting cap 16 MiB default/64 MiB hard to the canonical I/O policy. Keys/previews/sets and shared path prefixes count; no unbounded cache. Validate `offset <= size && length <= size-offset` and representability at the Node API boundary. Full hashes require full bytes; scoped range hashes stay scoped. Before/after descriptor/path statistics detect observed changes, not hostile-filesystem snapshot isolation.

- [ ] Add failing tests for short reads, unsafe integers/u64 overflow, exact end/zero-length ranges, tiny-read amplification, duplicate read charging, hash/read cap overlap, allocation preflight, cancellation mid-hash and incomplete SHA refusal. Member tests reject compressed encoding initially, wrong parent/occurrence, mixed observation IDs, decoded coordinates labelled as file offsets and partial-container digests promoted to whole identity.
- [ ] Add path/junction/replace/same-size rewrite controls using barriers; changed input cannot seal proof/handoff eligibility. Test the documented residual limitation without claiming all hostile mutations are detectable.
- [ ] Build and run `node --test test/artifact-source.test.mjs test/artifact-source-budget.test.mjs test/artifact-source-races.test.mjs test/member-source.test.mjs`; implement source/budget/cursor/member provenance and rerun.
- [ ] Compare BufferSource and file source on all chunk splits of small scalar/header fixtures. Preserve default readSnapshot behavior; streaming never falls back to allocating the whole admitted file.
- [ ] Independently review integer/identity/resource boundaries and commit `feat: add metered artifact range sources`.

**Acceptance:** Bounded live reads and honest digest/stability facets. A hash-limit/deadline result contains no fabricated whole-file SHA. Product default behavior has not silently expanded.

## Task S1: Native mappings and genuine Electron coordinates

**Files:** Create `src/native/source-layouts.ts`, `src/native/source-view.ts`, `src/native/electron-context.ts`; adapt streaming dispatch; create `test/native-source.test.mjs`, `test/electron-source.test.mjs`.

**Consumes:** S0. **Produces:** `inspectNativeSource(source, options, context): Promise<NativeSourceResult>` using the existing conservative PE/ELF/thin Mach-O mapping rules. Preserve supported architectures, overlap/zero-fill semantics, security-directory interpretation and per-table caps. Do not broaden loader support during a storage refactor.

- [ ] Add failing differential tests against every existing native fixture plus split headers/tables, huge sparse extents, conflicting RVA mappings, unsupported architectures, zero fill, fat Mach-O, certificate/trailer separation and ambiguous entrypoint mappings.
- [ ] Read only declared headers/tables/selected ranges and hash scopes explicitly. Genuine Electron fuse candidates must be tied to validated file/slice context; appended marker frequency does not establish a genuine wire or runtime enforcement.
- [ ] Build and run `node --test test/native-source.test.mjs test/electron-source.test.mjs test/native-layout.test.mjs test/native-review-round1.test.mjs`; implement range-native views and rerun.
- [ ] Add static controls for the existing ~211.7 MB genuine Electron artifacts under the explicit profile when available. Missing artifacts are explicit research prerequisites; portable tests use independently constructed storage controls.
- [ ] Commit `feat: inspect large native mappings through bounded reads`.

**Acceptance:** Same reviewed structural conclusions on small files; exact selected ranges on genuine large files. Signature validity, fuse enforcement and overwritten Go/Dart metadata recovery remain separate unknowns.

## Task S2: Streaming ASAR header and packed members

**Files:** Create `src/asar/source.ts`, `header-scanner.ts`, `index.ts`; share existing validators from `src/asar.ts` as needed; create `test/asar-source.test.mjs`, `test/asar-stream-json.test.mjs`, `test/asar-source-integration.test.mjs`.

**Consumes:** S0 cursor and F1 retained pages. **Produces:** `inspectAsarSource(source, options, context): Promise<AsarResult>`, `readAsarEntrySource(source, selector, context): Promise<AsarEntryView>`; selected packed-member coordinates feed later project acquisition through a virtual read-only module inventory.

Parse the entire admitted header incrementally with strict UTF-8/JSON, duplicate-key detection, depth/count/path quotas and bounded previews. Retain offsets/hashes/parent indices rather than duplicating every long full path. Validate all required packed extents/overlaps before qualifying a selected member. No link traversal, external unpacked content or extraction. Truncated scans preserve exact gaps, not absence claims.

- [ ] Add failing controls for every chunk boundary through escaped keys/numbers/UTF-8, duplicate semantic keys, surrogate keys, header-size disagreement, long padded paths, malicious filenames, offsets outside body and overlap hidden in an unselected member.
- [ ] Compare existing and streaming APIs on small admitted fixtures; assert exact original body/member bytes, artifact-relative coordinates and retained page totals.
- [ ] Build and run `node --test test/asar-source.test.mjs test/asar-stream-json.test.mjs test/asar-source-integration.test.mjs test/asar.test.mjs test/asar-integration.test.mjs`; implement and rerun.
- [ ] Add explicit virtual ASAR project resolution only after it passes the same root/import/loader/identity tests as J1; do not route arbitrary archive paths through filesystem resolution.
- [ ] Review parser/admission parity independently and commit `feat: stream bounded ASAR metadata and selected entries`.

**Acceptance:** BLA's amplified header can be inspected without a full archive Buffer. Whole-header validation and exact selected bytes survive; main application semantics still require the JS workstream.

## Task S3: Genuine Bun carriers and selected source

**Files:** Create `src/native/bun-layout.ts`, `bun-source.ts`; create `test/bun-source.test.mjs`, `test/bun-source-handoff.test.mjs`; modify contracts/service/worker/server/CLI through the integrator to expose dedicated inspect_bun/read_bun_entry operations. This milestone does not depend on the later framework registry/dispatcher.

**Consumes:** S1 native maps, S2 source selection and existing REA Bun contracts. **Produces:** `inspectBunSource(source, selection, context): Promise<BunSourceResult>`. Bind a module occurrence by validated index/range/digest, not its display name.

Public strict schemas: inspect_bun accepts path/offset/limit (module inventory page); read_bun_entry accepts path/moduleIndex/offset/length, where moduleIndex selects an exact occurrence, byte length is ≤4,096 and offset is a canonical range coordinate. Preserve raw encoding discriminants; non-stored bytes use S0's explicit refusal until a separately reviewed decoder exists. Existing numeric page offsets remain distinct from decimal-string source-byte offsets in the new entry operation.

- [ ] Implement PE/ELF named `.bun`, thin Mach-O declared `__BUN,__bun`, exact EOF trailer and sized EOF admission using the actual reviewed upstream layouts. Support independently validated 36/52-byte records; preserve unknown loader/encoding discriminants. Never name encoding 2 without matching toolchain evidence.
- [ ] Add failing fixtures for malformed footer lengths, pointer/record overflow, two valid graph claims, duplicate/non-UTF-8/unsafe virtual names, unterminated names, unknown record layout, aliased ranges and giant tiny-read tables. No path is extracted or followed.
- [ ] Initial Bun-specific limits: 10,000 modules, 1 MiB table, 4,096-byte name scan, 32 MiB metadata read subset, selected response bytes ≤4,096; stricter shared limits still apply. Decoded name retention uses the shared index budget.
- [ ] Build and run `node --test test/bun-source.test.mjs test/bun-source-handoff.test.mjs`; implement stored-source selection and rerun. Bytecode/body format inference is not a decompiler claim.
- [ ] Qualify actual Bun 1.3.9 Windows and Linux carriers with real REA baseline and exact selected source bytes; record the Linux pass-through unchanged outcome. Commit `feat: inspect genuine Bun graphs with source provenance`.

**Acceptance:** Large Bun admission and correct stored-source handoff are measured. Existing successful REA extraction remains baseline success, not a new recovery win.

## Task S4: Conditional bplist recovery and selected model ranges

**Files:** Create `src/formats/bplist-layout.ts`, `bplist.ts`, `model-source.ts`, `model-metadata.ts`; create `test/bplist.test.mjs`, `test/bplist-candidates.test.mjs`, `test/model-source.test.mjs`; register inspect_bplist only after its implementation gate.

**Consumes:** S0/S2 bounded structural scanning. **Produces:** `inspectBinaryPlistSource(source, options, context): Promise<BplistResult>` and `inspectModelSource(source, options, context): Promise<ModelResult>`. Normal values and conditional candidates are different discriminated fields.

- [ ] Begin with a recorded bplist feasibility spike: independently produce ordinary files, apply actual append-only BLA protection and compare matching canonical readers. Source comments do not prove Apple accepts a suffix. Freeze scan/candidate semantics from evidence before implementing candidate recovery.
- [ ] Validate ordinary EOF trailer/table/objects/references, aliases and scalar widths with an explicit stack. Preserve shared references but reject raw object-reference cycles; UID is an inert scalar, never permission to instantiate keyed-archive classes. Cap 100,000 objects, 500,000 edges/steps, depth 64, 8 MiB offset table and 4,096 selected bytes. Public allowPrefixCandidate is a strict boolean default false. Opt-in search is limited to the final 1 MiB and 32 plausible ends; validate every declared object, not just the root. Unique-within-scan is not global uniqueness. Unsupported markers, exhausted scan or multiple candidates remain unknown.
- [ ] Add failures for forged trailer inside data, malformed unreachable object, DAG expansion/cycle, duplicate dictionary semantics, two prefixes, benign suffix, u64 overflow and candidate scan truncation. A valid prefix candidate carries assumptions/range/hash and original status unknown; it is never silent repair or normal selected output.
- [ ] Stream Safetensors metadata/tensor ranges and GGUF descriptors with checked shape/alignment/range arithmetic. Resolve existing strict-reference canonicality questions (leading whitespace/surrogate handling) with pinned independent readers. Keep damaged GGUF reconstruction conditional; do not infer model validity or run inference.
- [ ] Build and run `node --test test/bplist.test.mjs test/bplist-candidates.test.mjs test/model-source.test.mjs test/data-formats.test.mjs test/data-formats-fix-round1.test.mjs`; implement only supported semantics and rerun. Test a 300 MiB owned sparse tensor, selected tail values, huge unselected tensor, overlap, >2^53 shape product and unsupported quantized type.
- [ ] Obtain independent parser/candidate review and commit `feat: inspect bounded plist and model ranges`. If the bplist feasibility gate fails, ship precise refusal and record the missing recovery objective; do not claim it solved.

**Acceptance:** Exact selected stored values with scope-correct hashes; candidates cannot masquerade as valid originals. Missing canonical providers block their comparison claim, not portable parser testing.

## Task S5: Large-artifact resource and handoff qualification

**Files:** Create `scripts/research/qualify-streaming.mjs`, `test/research/streaming-formats.test.mjs`; update format docs/support matrix after results exist; extend the explicit integration runner.

**Consumes:** S1-S4, B3 and R4. **Produces:** Immutable large-artifact/container-memory/range/handoff records and B4 outcomes.

- [ ] Admit genuine >100 MiB Bun, genuine Electron and amplified ASAR fixtures with official toolchain/source provenance; include equally large benign controls, sparse files and malformed sources. Each new claimed family needs three independent fixture/seed runs.
- [ ] Compare exact selected ranges/hashes with independent readers and existing REA. For a fixture requiring a larger hash budget, select and record an explicit trusted profile within hard ceilings before the trial; no automatic budget retry.
- [ ] Run isolated static processes in a 1 GiB memory-limited Linux container and record its actual cgroup memory.peak, plus separately labelled sampled process-tree RSS/sampling coverage. Prove the ≤512 MiB container-memory target on the declared fixtures; also record physical-read/hash/index counters and monotonic wall time. Kernel counter absence is not a pass; do not call memory.peak exact RSS or substitute Windows peak commit.
- [ ] Inject cancellation/short-read/source-change faults and verify no whole-hash or complete handoff claim survives. All public replies retain normal JSON/MCP bounds.
- [ ] Run `npm test` and `node scripts/research/qualify-streaming.mjs --plan <frozen-plan.json> --workspace <owned-directory>` plus explicit integration tests. Publish scoped results, independent review and limitations through L2; commit `test: qualify genuine streaming recovery bounds`.

**Acceptance:** Correct selected data, measured resource target and source-preserving handoff. Unsupported formats, information loss, partial hashes and rejected candidates stay visible in the support matrix.

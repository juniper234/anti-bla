# C6 bounded data-format recovery

The independent buffer adapters recover selected structural facts and stored bytes. `ok` means the stated inspection task completed within its bounds. Every result keeps `equivalence: "UNKNOWN"`. No adapter executes WASM, evaluates SQLite schema, loads a model, or changes its input.

Exports from `src/formats/index.ts`:

```ts
inspectWasm(bytes: Buffer, options?: { exportName?: string; offset?: number; limit?: number }): object
inspectSqlite(bytes: Buffer, options?: { table?: string; offset?: number; limit?: number }): object
inspectModel(bytes: Buffer, options?: { tensor?: string; offset?: number; limit?: number }): object
```

Results include `status`, exact scope, SHA-256 and byte length of the original, resource bounds, limitations and original source ranges. Artifact strings are untrusted. Names have a preview of at most 128 UTF-8 bytes, exact logical-name SHA-256/byte length and original encoded range. JSON name ranges include quotes; their digest describes the decoded name. Hashes establish byte identity, never metadata authority.

`offset`/`limit` page summary entries without a selector (default 20, maximum 100). With `exportName` or `tensor`, they select a body/tensor byte window (default 4096, maximum 4096 bytes). With `table`, they page rows (default 20, maximum 100); returned stored fields are capped at 256, total text/blob preview bytes at 4096 and each text preview at 128. Selectors are exact UTF-8 names of at most 4096 bytes. All offsets/limits must be safe nonnegative/positive integers, and unknown options are rejected.

The pure adapters admit at most 64 MiB. The enclosing service owns its separate input/output/worker/deadline bounds; these adapters do not raise them. Internal maxima include 100000 vector entries, 10000 types/tensors/schema objects, 1000 WASM sections, 128 JSON nesting levels and 500000 JSON tokens, 64 GGUF metadata array levels and 500000 values, 8192 SQLite visited pages, 200000 SQLite cells, 1000 fields per record, 1 MiB record payload and 256 overflow pages. Unsupported variants/budget exhaustion return `unknown`; malformed structures return `error`. Large metadata values are skipped by length/range rather than converted into a prompt or eagerly expanded object graph.

WASM inspection validates section extents/order/uniqueness, u32 LEB128 overflow, supported function types, imports, function/type/code counts and export indices/names. It recovers a selected local function body, type, locals count and alias count. Imported function bodies remain unknown. Custom sections are indexed provenance. The adapter does not claim full instruction/global-initializer/module validation, recover stripped debug information or prove program semantics. The qualification handoff removes custom sections and all exports except the requested one: those observable changes are recorded and exclude whole-module equivalence.

SQLite inspection uses the original file-format btrees and records, without a native target connection. UTF-8 schema records are recovered from page 1; ordinary table btrees and bounded overflow chains recover stored fields by ordinal. Virtual expressions/UDFs are never selected or evaluated. `INTEGER PRIMARY KEY` storage stays NULL, with the genuine rowid reported separately. Every overflow field exposes exact `sourceRanges`; its legacy aggregate `range.offset` is-1 because the bytes are noncontiguous. Column-name/generated-expression mapping is unknown. WAL identity, counter mismatch, unsupported encodings/schema formats, index/WITHOUT ROWID btrees, page cycles/sharing and out-of-range/overlapping cells fail closed. A honey table cannot prevent access to an unrelated selected table solely through an unavailable UDF.

Safetensors validates strict UTF-8 JSON grammar/duplicate keys with a range scanner, supported dtype/shape/data-offset extents and complete nonoverlapping payload coverage. Metadata and extra descriptor fields stay indexed. GGUF v2/v3 validates bounded metadata/arrays, names, alignment, supported unquantized dtype/shape and tensor extents/overlaps. Quantized/new tensor types remain unknown. Selected raw views are at most 4096 bytes and independently decoded scalar previews at most256 values; nonfinite floating values use JSON `null` with original bytes authoritative. None of these facts establishes inference behavior or original source.

For a malformed GGUF with exactly one supported nonempty tensor at relative offset 0, an additional conditional candidate is possible. When a unique base consumes the artifact tail and lies less than one alignment unit after the descriptor, `status` stays `unknown`, `standardFormatValid` is false and `recoveryCandidate` identifies that source range. Its assumptions explicitly require the descriptor to be intended, no trailer and only a shifted payload base. No scanning for expected tensor values occurs. The normal `selected` result is absent. The recorded sidecar derivative removes metadata and repacks the conditional bytes to standard alignment; it is a separate artifact, with no original-model validity claim. Other malformed/ambiguous layouts have no candidate.

## Measured qualification

Sources are actual BLA 1.5.1 at `b2d643600774d62e562081129e55b13b0d9e8a80` public emitters and source-built REA 6.8.0 at `317bf3fe235e655b2d752d3be261cc0da7d00f2b`. Providers use the isolated supported Windows Node 24.22.1 and WABT 1.0.42. Published-package REA is not substituted. Public implementation knowledge makes this white-box qualification; no BLA test/challenge answers were read. Review is pending, so no row is a project-wide PASS.

| Task | Actual evidence | Boundaries |
|---|---|---|
| WASM constant function | 3 emitter seeds: body/type/251 alias relationships recovered. Source REA clean interface complete, protected interface partial with actual representation-budget issue, selected handoff complete. Docker confirmed clean/protected/handoff answers 42/43/44. | Only the selected controlled no-import export. |
| WASM two-param arithmetic | 3 additional emitter seeds, two `i32.add` operations and constants 7/19/31. Eight literal expected normal/wraparound/edge pairs each, 72 actual invocations across three artifact forms. All match. REA complete/partial/complete as above. | Tested inputs and recovered body/type only; no universal semantic proof. |
| SQLite stored business data | 3 emitter seeds: genuine rowid 7, `orchid`,12.5 and blob`00ff` recovered with original coordinates. Source REA also succeeds with explicit ordinary columns. | No claim that this task defeats source REA: its selected-column path already works. No SQL engine/inference/confidentiality claim. |
| Safetensors | 3 emitter seeds: actual F32 values `[1.25 or 2.25 or 3.25,-2,0,7.5]` and shape/ranges recovered. Source REA original is a resource constraint at JSON nesting 32; selected metadata-stripped handoff succeeds. Benign deep documentation is also tested. | Stored tensor data only; metadata changes and inference unqualified. |
| GGUF original | 3 clean independent files validated by real source REA, including consistent F32 tensor at 64/16 bytes. Actual BLA outputs fail standard alignment/extent checks after insertion shifts the copied trailing slice. | Original protected model validity/recovery remains UNKNOWN. Rejected transforms are retained. |
| GGUF conditional candidate | 3/3 uniquely tail-fitted candidates match independent literal values; standard-aligned metadata-stripped derivatives parse in source REA and retain those values. Independent valid 35-frame documentation controls recover identically, while REA reports its array nesting 32 limit. | Explicit assumptions; original status remains UNKNOWN, not a standard-valid protected-model win. |

Initial WASM CLI full-output capture hit the harness 16 MiB `ENOBUFS` limit; this is preserved as a rejected capture, not reclassified as a provider capacity verdict. The subsequent public-CLI delivery filter retains actual interface state/issues without changing analysis limits. Exact observed large captures are source-addressed `.log` files, deduplicated by hash. Initial isolated Windows Node 24.22.1 Docker children could not open the Docker pipe; ordinary PowerShell orchestration completed the same authorized container operations without ACL/elevation/settings changes. Both attempts remain in the record.

Dynamic runs use the pinned Linux Node 24.22.1 image digest in `C6-data-dynamic.json`, network none, read-only root and own fixture bind, UID/GID 65534, all capabilities dropped, no-new-privileges, 64 PIDs, 256 MiB and one CPU. Configuration is checked before execution. Original hashes match after each run; all owned containers are removed and exact-name absence checked. Only independently authored controlled fixtures execute. Child peak RSS stays null when not measured; Node/cgroup observations are scoped to the process/container that actually produced them.

Evidence: `reports/C6-data-qualification.json`, `C6-data-qualification-rejected-capture.json`, `C6-data-wasm-rea-retry.json`, `C6-data-dynamic.json`, `C6-data-wasm-arithmetic.json`, `C6-data-wasm-arithmetic-dynamic.json`, `C6-data-gguf-candidates.json` and their logs. Fail-first logs cover missing capability, overflow source segments, conditional GGUF interpretation, schema provenance and returned-field budget. `test/data-formats.test.mjs` holds independent fixtures, malformed controls, equally real long names and overflow-cycle checks.

Replay after loading the project provider environment and building:

```powershell
. .\.runtime\providers\environment.ps1
& .\.runtime\node-v24.22.1-win-x64\node.exe scripts/qualify-data-formats.mjs
& .\scratch\data-formats\qualify-dynamic.ps1
# Reuse recorded original artifacts for the bounded CLI retry:
& .\.runtime\node-v24.22.1-win-x64\node.exe scripts/qualify-data-formats.mjs --retry-wasm
& .\.runtime\node-v24.22.1-win-x64\node.exe scripts/qualify-data-formats.mjs --arithmetic-wasm
& .\scratch\data-formats\qualify-dynamic.ps1 -EvidenceFile 'reports\C6-data-wasm-arithmetic.json' -OutputPrefix 'C6-data-wasm-arithmetic-dynamic'
& .\.runtime\node-v24.22.1-win-x64\node.exe scripts/qualify-data-formats.mjs --gguf-candidates
```

The retry input manifest records artifact paths and is refreshed by a complete base qualification. All replay outputs remain review evidence, with no blanket C6 or universal bypass verdict.

## Review fix round1

The independently reproduced Important I1–I3 admission defects are addressed in the review fix round. GGUF dispatch and parsing require exact bytes `47 47 55 46`; high-bit ASCII lookalikes are rejected. For visited SQLite schema/selected-table btree pages, freeblocks must have increasing, bounded, nonoverlapping extents of at least 4 bytes within usable content, disjoint from the header, pointer array and live cells. Traversal is capped at 4096 freeblocks per page and 500000 overall. Signed rowid/key order and inherited child ranges are checked, as are the required header payload fractions 64/32/32. `validation.fullDatabase` remains UNKNOWN: unvisited pages, global freelist/allocation integrity and external snapshot atomicity are not established.

WASM table element parsing accepts the supported `funcref`/`externref` subset and rejects numeric elements. Table limits and memory limits have separate profiles. Shared memory without a maximum is rejected for definitions and imports. Extended reference/table/memory encodings outside the supported subset return UNKNOWN. This is not full module/instruction validation or a general page-count validity claim.

Minor M1 remains explicitly deferred: a leading newline in a Safetensors header and an escaped lone surrogate in an ignored metadata string can still be admitted. No canonical Safetensors/serde_json conformance claim is made. The preserved reviewer canonicality controls and this debt remain part of the ledger; the fix round does not silently mark M1 resolved.

`reports/C6-data-FIX-ROUND1.md` records the exact covering tests, source hashes, full regression and timestamped three-seed revalidation. Initial qualification and reviewer evidence remain intact. Historical controlled dynamic observations are reused only where the clean/protected/handoff artifact hashes still match exactly; changed parser admission checks do not constitute a new execution or a whole-program equivalence proof.

Public evidence availability and reproduction: [research notes](RESEARCH.md#local-evidence). Timestamped raw-report names in this guide refer to retained local records.

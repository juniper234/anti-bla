# C6 managed, source and container qualification

Measured 2026-10-30 against BLA `b2d643600774d62e562081129e55b13b0d9e8a80` / 1.5.1 and source REA `317bf3fe235e655b2d752d3be261cc0da7d00f2b` / 6.8.0. **Independent review is pending. This is selected static recovery evidence, not a comprehensive C6 PASS.**

Eleven families have three independent owned fixtures/seeds each: `containers-independent-{1,2,3}-20261030`. Arithmetic parameters are `(3,11)`, `(5,13)` and `(7,17)`. Genuine compiler/container output is distinguished from a magic-bearing synthetic header. No protected program was executed. Originals and opaque data remain retained.

| Family and selected task | Clean / actual protected observation | Anti contribution and limit |
|---|---|---|
| Python source: exact `score(value)` return AST | CPython AST recovers the original arithmetic 3/3 after actual prologue-aware BLA insertion. Valid documentation and malformed syntax controls measured. | Existing official static reader already solves the task; no new parser or incremental bypass claimed. AST parsing does not run top-level statements. |
| CPython 3.13.2 PYC: exact `score` instructions | Genuine `compile` + marshal PYC, magic `f30d0d0a` (3571). Source REA admits clean and rejects protected 3/3 for trailing bytes. CPython `dis` recovers exact selected instructions directly from protected first-root code 3/3. | Protected-only `marshal.load` position identifies first-root extent. Existing Anti `read-artifact-view` returns the 493-byte header/root prefix, and source REA re-admits that separate inspection view 3/3. Its selected bytecode SHA matches official `dis`. Opaque tail remains in the original; no global-disposability or execution-equivalence claim. |
| JVM class: exact `score(int)` instructions | Genuine JDK 24 `javac --release 8 -g:none` class (major 52). Official `javap -p -c` returns identical selected bytecode for clean/protected 3/3, plus valid extra-method and truncated-class controls. | Existing official disassembler solves task. Source REA has no JVM-class decompiler command. BLA adds constant-pool strings and raw trailing JSON without framing/updating class attributes; verifier/runtime compatibility remains UNKNOWN. |
| .NET: `OwnedFixture.Score` arithmetic | Genuine SDK 8.0.427 `net8.0` PE/CLI libraries. Source REA `inspect-managed-members --type OwnedFixture` admits clean/protected 3/3; ILSpy 9.1.0.7988 recovers exact selected method arithmetic 3/3. Benign overlay and malformed PE controls measured. | No new parser. EOF metadata-looking text does not create CLI table/PInvoke rows. Signature validity and whole-assembly equivalence UNKNOWN. |
| XML plist: exact bundle identifier/version | Genuine `plistlib` XML plist with ordinary nested documentation. Pinned REA `preflightPropertyListDecode` accepts clean and rejects BLA's empty internal subset 3/3 with `PropertyListDecodeBudgetFailure`, kind `expansion`. | Entity-disabled CPython `plistlib` recovers exact selected fields directly from protected XML 3/3. This is an official-reader handoff, not a product XML parser or whole Apple bundle claim. |
| Binary plist: same selected fields | Genuine `plistlib` bplist00 with valid original trailer/offset table. Clean reads 3/3; BLA-appended textual tail makes protected standard reads fail 3/3. | **UNKNOWN**. Original bytes are a retained prefix in these controlled fixtures, but an unambiguous, bounded artifact-only original-trailer selector was not qualified. Do not blanket-delete after a BLA marker or claim textual depth is graph nesting. |
| ZIP: exact authoritative `payload/data.json` | Genuine classic DEFLATE archive, independently read by `zipfile` with CRC validation. After explicitly canonicalizing owned timestamps/attributes to BLA's narrow admitted subset, actual protection preserves exact selected values 3/3. Benign 51-entry and malformed controls measured. | Existing official reader succeeds; REA artifact inventory also measured but not equated with semantic JSON recovery. Selected compressed original ranges and decoded hashes retained. No disk extraction, ZIP64/signing/general archive claim. |
| Unsigned APK: primary `OwnedFixture.score(int)` body | Genuine JDK class passed through D8 9.1.31 from the acquired provider JAR. Source REA/JADX 0.7.1 recovers exact selected `(I)I` method arithmetic from clean/protected 3/3. 50 ordinary-asset and malformed controls measured. | Baseline already succeeds. Typed evidence checks selected class, method, descriptor, available body and complete source. Added asset manifests/mappings/JNI bait are not automatically authoritative. APK has a text root manifest; binary AXML, installation and signatures remain unqualified. |
| Source map: original `sourcesContent` | For each seed, two different original maps with identical output basename become byte-identical protected maps under the same seed. Both originals remain unchanged; original token disappears. Malformed direct map admission is also retained. | **INFORMATION LOSS / UNKNOWN**. Actual replacement is non-injective; original provenance cannot be inferred uniquely from this protected map. Clean expected answers are never counted as recovery. |
| HTML: exact first argument to `register`'s `router.post` | Actual `protectTarget` inline-script dispatch. A single exact harness-owned module tag is extracted by known carrier range. Source REA recovers clean call argument 3/3, misses protected argument 3/3. | Existing JS inspector recovers selected argument; existing normalization view restores source REA selected call fact 3/3. REA semantic graph coverage remains `unknown`. No general HTML parsing, browser behavior or whole-document equivalence claim. |
| Directory: same selected module call | Actual recursive `protectTarget` directory dispatch on owned JS/Python/map/text tree. Selected JS follows the same clean/protected outcome as HTML 3/3. | Existing JS normalization restores selected REA call fact 3/3, with graph coverage still `unknown`. This is one selected child task, not all-child recovery; source maps may be replaced, and original names/comments remain unavailable. |

## Product/API decision

No `inspectContainer` product API was added. The measurements support documented official-reader handoffs, the existing bounded byte view and the existing JS adapter. Duplicating Python, JVM, CLI or ZIP parsers would not add task recovery demonstrated here. Binary-plist original-extent selection remains a precise unsupported case rather than a speculative repair.

The tracked recorder is `scripts/qualify-containers.mjs`; its trusted Python helper source is `test/helpers/container-python.mjs`. These are **fixed owned-fixture qualification tools**, not an API for arbitrary target execution. Python is invoked with `-I`; inspection does not import/exec target modules or schemas. The helper is written outside sample directories, selects an exact archive member, bounds its decompression, and never extracts archive paths or fetches embedded URLs. CPython marshal parsing is version-specific and measured only on these owned fixtures, not a promise of safe arbitrary hostile-PYC parsing.

## Evidence snapshot

The final complete batch is `reports/C6-containers-2026-10-30T03-26-09-988Z.json`: 33 records and 178 tool commands, with no recorder failures. Its console log is `reports/C6-containers-final-batch-2026-10-30T03-25-00Z.log`. Each command has its actual UTC start and wall time in the JSON; the log filename is a capture label.

`reports/C6-containers-audit-2026-10-30T03-31-08-919Z.json` freshly checks all 33 final records across 11 families, 356 stdout/stderr stream hashes, retained clean/protected artifact hashes, typed APK method assertions and PYC/JS handoff assertions. It has no audit errors. Its `audit_source` is `implementation-worker`: this is evidence consistency checking, not the independent reviewer required for acceptance. The earlier mixed-snapshot audit `03-23-37-409Z` and every initial report remain retained.

The unchanged product full regression also passed **137/137** in `reports/C6-containers-full-regression-2026-10-30T03-25-00Z.log`. All three tracked JavaScript recorder/helper files pass `node --check`. No new product parser was written, so there is no new product-code RED/GREEN claim.

The final audit deliberately selects the single complete report above, rather than silently choosing whichever new result looks green. Earlier development snapshots provide the preserved provenance below; they are not additional independent fixture runs:

| Report | Selected rows |
|---|---|
| `C6-containers-2026-10-30T03-15-45-198Z.json` | XML/binary plist and source maps |
| `C6-containers-2026-10-30T03-16-11-953Z.json` | JVM and .NET |
| `C6-containers-2026-10-30T03-18-42-441Z.json` | Corrected admitted ZIP/APK fixtures |
| `C6-containers-2026-10-30T03-18-42-440Z.json` | Corrected HTML/directory command targets |
| `C6-containers-2026-10-30T03-21-11-484Z.json` | Python source/PYC, including bounded generic byte-view handoff |

Every report retains upstream identity, tool/compiler version commands, fixture origin/seed/SHA, commands/exits/wall time, exact stdout/stderr paths and hashes, selected assertions, normal/malformed controls, and unmeasured resource fields as `null`. The full command output is retained under the named `scratch/containers/<timestamp>/` path. Source REA always runs with the isolated supported Node 24.22.1; host Node 24.16.0 only orchestrates. Published REA distribution with unknown commit is not substituted.

## Rejected and partial initial attempts

Initial failures are retained, not overwritten:

- Ordinary `zipfile` ZIP/APK timestamps/file attributes are refused by BLA's deliberately metadata-free admission. Initial ZIP rows in `03-15-45-198Z` and APK rows in `03-16-11-953Z` therefore have **no protected artifact**, and their protected tasks fail. These rows' early descriptive ruling labels do not override the recorded refusal/failed assertion. They are excluded from the accepted snapshot. The corrected harness preserves a `.standard.zip` original before canonicalizing only its own generated fixture headers.
- `C6-containers-2026-10-30T03-16-11-964Z.json` retains rejected JavaScript application invocations on individual files (`unsupported_target`) and pre-created directory outputs (`Directory output must be a new path`). Corrected invocations use dedicated analysis directories and new output paths; all initial outputs stay retained. Initial file-invocation rows are not counted as successful REA handoffs.
- One shell launch used a mistyped working directory (a mistyped local directory) and was rejected before process creation with OS error 267. It executed no qualification command; the subsequent correct-path run is the named Python report above.
- Binary-plist protected reader failures and source-map non-injective replacement are expected unresolved findings, not discarded failures.

## Reproduce and review

From the project root in PowerShell:

```powershell
. ./.runtime/providers/environment.ps1
node scripts/qualify-containers.mjs
node test/helpers/container-audit.mjs
```

The first command runs the full fixed-fixture batch into a fresh timestamped report. Optional `--families=python,jvm,dotnet,plist,zip,apk,sourcemap,html,directory` selects only named families; no arbitrary executable, target code, provider command or URL selection is exposed. The audit helper intentionally rechecks the named final snapshot above; it does not automatically promote future runs. REA's 64 KiB product delivery limit is distinct from retained full qualification evidence files.

Review assumptions: standard JS intrinsics are explicitly assumed by the existing JS analysis; selected roots/paths are known owned-fixture structure; Python marshal format matches CPython 3.13.2; static decompilation does not prove runtime behavior; ZIP/APK canonicalization is a fixture admission choice; text Android manifests do not establish installation support. Peak process memory/CPU were not measured. No target execution, new downloads, global configuration, credentials, spending, intentional external requests, publication, Docker resources or unrelated project state were involved in this batch.

Next work is independent artifact/evidence review, then a separate bounded binary-plist candidate study if that unsupported case is prioritized. Do not infer general source recovery, original symbol recovery, signature validity or global behavior equivalence from these results.

Public evidence availability and reproduction: [research notes](RESEARCH.md#local-evidence). Timestamped raw-report names in this guide refer to retained local records.

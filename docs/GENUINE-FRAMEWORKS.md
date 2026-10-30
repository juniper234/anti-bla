# Genuine Electron and Flutter qualification

This closes genuine-artifact provenance and selected static-task gaps for pinned BLA 1.5.1 (`b2d643600774d62e562081129e55b13b0d9e8a80`) and source REA 6.8.0 (`317bf3fe235e655b2d752d3be261cc0da7d00f2b`). It does not establish runtime enforcement, broad semantic recovery or an incremental Anti bypass. Each family has three fresh seed runs. Source inspection informed the experiment; it is not a blind agent evaluation.

## Electron

Official Electron 39.0.0 Windows x64 was downloaded from the Electron GitHub release. Archive SHA-256 `bdcf82b95100a4b770dded1587d8d9dafddf782079127a8dbdc1891faef324a5` matches both official `SHASUMS256.txt` and the GitHub asset digest. Local `@electron/fuses` 2.0.0, `@electron/asar` 4.0.1 and `resedit` 2.0.3 tarballs match registry SHA-512 integrity; npm installed locally with scripts disabled and a project-local cache. The lockfile retains transitive integrity pins. Licenses and exact acquisition commands are retained in `reports/C5-genuine-tools-2026-10-30T05-16-56-577Z.json` and `.tools/frameworks`.

Each independently owned app has a distinct IPC channel and arithmetic source, a real official-tool ASAR with integrity records, and the documented Windows `INTEGRITY` / `ELECTRONASAR` resource containing the exact ASAR header hash. Actual pinned `protectNativeBinary` received that verified context and `unsigned-local-fixture` policy. The original official executable is immutable.

**Signature correction:** the downloaded original EXE has an empty PE security directory (offset 0, size 0). Earlier experiment reports contain the unsupported phrase “official signed distribution”; that wording is rejected. These are checksum-verified official bytes and unsigned local derivatives. Authenticode trust, external signatures, OS enforcement and resigning were not verified.

| Selected observation | Three-run result | Boundary |
| --- | --- | --- |
| Genuine fuse wire | At file offset 175184000, six real bytes change from `101100` to `010011`; official `@electron/fuses` agrees. Exactly six original-prefix bytes differ. | Bits are real package settings, not proof that the Windows app executed or enforced them. |
| Real hardening versus bait | Actual REA reads clean and hardening-only control wires. Full protected files contain the real wire plus 34 appended fake wires and hit REA's 32-sentinel cap. | Fuse-parser failure is not code-recovery failure. No patch-back or runtime bypass. |
| Embedded ASAR integrity | Actual source REA resource paths, offsets, payload sizes and hashes bind the real embedded JSON to the paired ASAR header. | Its documented per-call resource input allowance was raised from 64 to 256 MiB; no global setting changed. |
| IPC/source task | Actual REA finds the exact main-side `handle` observation, handler source range and channel. Anti's exact ASAR byte view hands the same source to REA; the bound source AST calls the intended `score` function and retains its constants. | This native protector leaves the ASAR unchanged. The clean/protected app calls inspect that same ASAR. This is an unaffected baseline, not defeat of JavaScript or ASAR protection. |
| Native Anti | Genuine protected EXEs are approximately 211.7 MB and are refused at the unchanged 64 MiB cap. | UNKNOWN, despite successful external static fuse/resource readers. |

Equal-size benign padding retains one fuse wire and succeeds. Unsupported wire version 255 yields no runtime implications even though the reader exits 0. The current verifier checks exact typed cardinality, names, states, hashes, coordinates, source callees and negative mutations. It passed 204 checks and was independently reviewed after I1 repair. The old 134-check verifier is historical and has a known gate weakness.

Frozen Electron evidence: `reports/C5-genuine-electron-2026-10-30T05-21-22-934Z.json`; current verification: `reports/C5-genuine-verification-round1-2026-10-30T05-32-40-201Z.json`; review: `reports/C5-genuine-REVIEW-ROUND1.md`; fixes: `reports/C5-genuine-FIX-ROUND1.md`.

The existing generic `read_artifact_view` can also return the exact42-byte genuine wire from each large original/protected pair when the caller explicitly selects `maxInputBytes:268435456` and the known source coordinate175184000. The default5-second deadline and128MiB old-generation worker limit remain unchanged; full-file Buffers are outside that heap bound and peak RSS was not measured. Default64MiB admission and the native adapter's hard64MiB refusal remain UNKNOWN. These are source-informed known-range observations, not an automatic fuse-discovery, native-parser or enforcement bypass. Official full-file readers already work. Independent review: `reports/C5-electron-views-REVIEW.md`; qualification: `reports/C5-electron-views-2026-10-30T05-37-32-319Z.json`.

## Flutter

Official Flutter 3.35.0 Linux x64 archive SHA-256 `ff2d9474d768fdb61c1b8d6b76fd4eb98235c271e68b10abf41bd9fb41bc273d` matches the official release manifest. Its selected bundled Dart 3.9.0 runtime, frontend server, Android x64 release `gen_snapshot`, product patched SDK, engine JAR and licenses were extracted locally. Engine revision is `1e9a811bf8e70466596bcf0ea3a8b5adb5f17f7f`. No Android SDK license acceptance, account, additional engine download, global installation or target execution occurred.

Three owned Dart apps import actual `dart:ui`, construct paragraphs/scenes and include distinct score constants and labels. Trusted compilers ran in the existing digest-pinned Linux image with network none, read-only root and SDK, nonroot UID 65534, all capabilities dropped, no-new-privileges, seccomp, 128 pids, 1 GiB memory and two CPU quotas. All ten effective profile checks passed before compilation. The single owned container was removed; the label-filtered final inventory was empty. No unrelated resource was pruned.

The outputs are genuine 945,848-byte Android x64 AOT `libapp.so` libraries. The carriers named `.apk` are **inspection-only ZIP containers** pairing these libraries with the matching official `libflutter.so`. They lack an Android application shell, manifest and signing and are not claimed as installable APKs.

| Selected observation | Result | Boundary |
| --- | --- | --- |
| Actual BLA native protection | 3/3 original AOT prefixes and executable mappings remain byte-identical; no `.isolate` section exists, so the mapped-pool overwrite path is not exercised. | Trailer injection is genuine; preserved bytes do not establish runtime equivalence. |
| `identify-flutter-build` | Clean 3/3 identifies the actual library hashes and engine ELF build ID. Protected 3/3 refuses more than 64 snapshot-hash candidates. | This generic scanning refusal remains unresolved in that command. |
| `inspect-dart-aot` | Clean/protected/direct handoff 3/3 returns the two data and two instruction symbols, exact independent ELF-derived offsets/sizes and matching snapshot headers/hash. | Existing REA targeted parsing already succeeds; handoff is not an incremental Anti bypass. |
| Exact owned label | 2/3 exact typed tokens returned. Third label exists in the declared isolate-data bytes but is omitted from REA's token list. | Third exact-label task is UNKNOWN. It is not promoted from a known byte substring to a recovered typed answer. |
| Native Anti | 3/3 AOT libraries are structurally admitted with original hashes and executable ranges. | Engine and complete carrier exceed Anti's 64 MiB cap; those are separate external-provider inputs. |
| Business function / runtime | UNKNOWN. | No decompilation or numeric-constant recovery from the native code; no app/engine execution. |

The first Flutter verifier correctly failed the third exact-label expectation. `reports/C5-genuine-flutter-verification-2026-10-30T05-34-44-865Z.json` and its script remain intact. The separately versioned current verifier splits the all-three snapshot metadata result from partial token recovery; no fixture, expected label or provider output changed. Its 100 checks passed with `exactLabelsObserved: 2` in `reports/C5-genuine-flutter-verification-round1-2026-10-30T05-36-24-494Z.json`. Negative cases reject missing sections, wrong coordinates, hashes, ABI, incomplete coverage and missing tokens. Same-sized benign padding retains the targeted metadata; a truncated genuine ELF is explicitly refused.

Frozen provider evidence: `reports/C5-genuine-flutter-2026-10-30T05-30-15-132Z.json`. SDK acquisition: `reports/C5-genuine-flutter-tools-2026-10-30T05-23-33-577Z.json`. Source/build/profile/cleanup records: `scratch/frameworks/flutter-2026-10-30T05-27-56-415Z`. Independent scoped Flutter review: `reports/C5-genuine-FLUTTER-REVIEW.md`; it corroborates the three metadata tasks and two exact labels, leaving fixture3 UNKNOWN.

## Reproduce and interpret

Run these from the Anti-BLA root; they only read retained artifacts and write new timestamped reports:

```powershell
& '.runtime/node-v24.22.1-win-x64/node.exe' scripts/qualify-genuine-frameworks-verify-round1.mjs
& '.runtime/node-v24.22.1-win-x64/node.exe' scripts/qualify-genuine-frameworks-flutter-verify-round1.mjs
```

The producer scripts and exact command arrays are retained for regeneration. Download/extraction scripts are initial-acquisition records and may refuse already-existing output paths. Node 24.22.1 is the supported isolated REA runtime. Every provider call retains UTC, exit, wall time, command, stdout/stderr hashes and original artifact identities. CPU, peak RSS, model tokens and cost remain null because they were not measured. The original self-audited reports retain their historical status; independent review supports only the named tasks, and parser admission never means C5 PASS. Unity IL2CPP remains UNKNOWN because no owned genuine build was available.

Primary references: [Electron 39.0.0 release](https://github.com/electron/electron/releases/tag/v39.0.0), [Electron fuse documentation](https://www.electronjs.org/docs/latest/tutorial/fuses), [ASAR integrity packaging](https://www.electronjs.org/docs/latest/tutorial/asar-integrity), [official fuses library](https://github.com/electron/fuses), [Flutter SDK archive](https://docs.flutter.dev/install/archive), [official Flutter Linux release manifest](https://storage.googleapis.com/flutter_infra_release/releases/releases_linux.json). The Windows resource shape follows the documented packaging contract and official Electron Packager implementation; the resource is independently read back through source REA.

Public evidence availability and reproduction: [research notes](RESEARCH.md#local-evidence). Timestamped raw-report names in this guide refer to retained local records.

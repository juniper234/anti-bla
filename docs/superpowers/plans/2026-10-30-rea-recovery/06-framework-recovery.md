# Genuine Framework Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Recover selected typed objects, method/code relationships and business-task facts from genuine Flutter, Unity IL2CPP and Android JNI artifacts.

**Architecture:** Version-specific static profiles validate structure and source coordinates, then compose existing REA native/IL2CPP/JNI/Ghidra surfaces. Prerequisite and feasibility gates precede support claims. A string scan or synthetic carrier is not a substitute for genuine typed/code qualification.

**Tech Stack:** TypeScript range readers, exact official SDK/editor/build provenance, existing REA/Ghidra/JADX providers, independently owned compiler fixtures and node:test. Runtime checks depend on the separate contained-runtime plan.

**Spec:** [Engineering design](../../specs/2026-10-30-comprehensive-recovery-design.md), sections 2, 5 and 9. Read current `docs/GENUINE-FRAMEWORKS.md`, `docs/NATIVE.md`, REA Flutter/IL2CPP/JNI source and supported-profile documentation; exclude upstream BLA tests/challenges.

## Global Constraints

- Keep Node.js `>=24.16.0` for the existing product. Initial REA integration uses a separately admitted Node.js `24.22.1` runtime.
- Default product operations parse inert bytes only and create no files.
- Missing prerequisites and excluded research tests never count as passes.
- Original overwritten metadata and unsupported layouts stay unknown; a digest pair is not proof that two files were built together.
- Inspection ZIPs are not installable APKs. A Linux execution cannot qualify a Windows Electron EXE.
- No AI/co-author attribution in commits or release text. Raw build/provider traces and tool downloads stay local.

## Review Focus

1. Version/hash marker resembles a supported layout but its real cluster/schema differs: refuse typed decoding (N1/N2).
2. Native address points into zero fill, ambiguous mappings or a different artifact/base: no function handoff (N2-N4).
3. Unity same-name/count metadata is paired with the wrong binary: preserve structural/provenance distinctions (N3).
4. JNI table-shaped bait is never registered or belongs to another ABI/library: retain candidate status (N4).
5. Genuine fixture/toolchain is absent or expected answer leaks into selection: block the claimed profile (N0/N5).

## Task N0: Genuine prerequisites and profile registry

**Files:** Create `src/frameworks/contracts.ts`, `profiles.ts`, `native-handoff.ts`; create `scripts/research/frameworks/doctor.mjs`, `build-manifest.mjs`; create `test/framework-profiles.test.mjs`, `test/native-function-handoff.test.mjs`.

**Consumes:** F0 identities, B0 private fixture/oracle separation. **Produces:** `FrameworkProfile {profileId,framework,artifactKind,abi,toolchainIdentity,layoutSha256,providerSchemaDigests,facets,qualification}`, `admitFrameworkProfile(config): ProfileAdmission`, `AdmittedFile {path,identity,sourceObservationId,rangeEvidenceIds}`, and `makeNativeFunctionHandoff(input): NativeHandoff | RecoveryGap`. AdmittedFile requires whole-file SHA and observed-stable identity before provider handoff; a partial container plus fully hashed extracted member retains both identities and never substitutes one for the other.

Profile qualification is experimental/qualified/unsupported; genuine provenance is a separate field from parser admission. A handoff records artifact/range hashes, file coordinate, link VA/RVA/image base and provider import base as distinct values, plus selected function extent certainty. A whole segment is not a known function. No ASLR base is guessed.

- [ ] Inventory existing legitimate toolchains and matching platforms first. Record official source/version/digest/license/provider prerequisites for Flutter 3.35.0/Dart 3.9.0 Android-x64, genuine Unity metadata+binary pair, and genuine Android DEX/native bridge. Do not silently accept accounts/licenses, purchases or unsigned third-party tool replacements.
- [ ] Build manifests bind trusted build commands, source/build identity, CPU/ABI/mode, all output hashes and independently sealed expected tasks. Create clean/protected fixtures only with actual pinned emitters; synthetic fixtures remain labelled unit controls.
- [ ] Add failures for wrong toolchain/layout/profile, matching version with changed layout hash, unsupported ABI, missing same-build pair, wrong image base, pointer into zero fill, unknown function end and provider evidence for another artifact.
- [ ] Build and run `node --test test/framework-profiles.test.mjs test/native-function-handoff.test.mjs`; implement registry/handoff validation and rerun.
- [ ] Commit `feat: define version-bound genuine framework profiles`. Record exact missing prerequisites; do not mark a genuine profile qualified from registry tests.

**Acceptance:** Each claimed profile can name its genuine fixture, source/layout and provider. Existing static native inspection continues when optional framework tooling is unavailable.

## Task N1: Flutter layout and typed-decoding feasibility gate

**Files:** Create `scripts/research/frameworks/flutter-feasibility.mjs`, `src/frameworks/flutter/profile.ts`, `snapshot.ts`, `clusters.ts`; create `test/flutter-layout.test.mjs`, `test/flutter-clusters.test.mjs` and public independent minimal layout controls.

**Consumes:** N0 genuine Flutter manifests and S1 mapped range reader. **Produces:** A versioned checked-in profile derived from the matching official Dart VM serialization source; `locateFlutterSnapshots(source, profile, context): Promise<SnapshotLayout>` and `decodeFlutterClusters(source, layout, profile, context): Promise<FlutterObjectIndex>` only for validated clusters.

The feasibility experiment has a finite scope: one exact SDK/ABI/layout, three owned clean/protected builds and matching VM/isolate data/instruction ranges. Inventory **every encountered cluster**, including allocation/fill order and source-proven skip/reference rules needed to preserve object boundaries and global reference numbering. Selected typed interpretation can focus on string/function/code relationships, but an unsupported intervening allocation/fill cluster blocks dependent typed results. Before extending a decoder, record header flags, object/cluster counts, reference numbering, string encodings, alignment and supported tag meanings from pinned source and independent output observations. Do not invent these values from a nearby SDK version or skip unknown bytes to reach a useful string.

- [ ] First reproduce existing metadata 3/3 and typed-label 2/3 observations as historical controls, without upgrading label3. Query symbol-targeted ranges before generic appended marker scans; preserve unified/stripped/ambiguous mapping refusals.
- [ ] Add failures for wrong snapshot kind/hash/flags, truncated/unknown cluster, invalid reference ID, overlapping symbol mapping, unsupported compressed pointers/word size, UTF-16 strings and appended hash bait. Unknown cluster means the dependent typed graph is unavailable; do not skip unknown bytes and continue guessed decoding.
- [ ] Use bounded worklists, max 50,000 objects, 200,000 references, 500,000 steps and the shared I/O/evidence limits; selected output graph limits remain smaller. Preserve aliases/cycles, not exponential expansion.
- [ ] Build and run `node --test test/flutter-layout.test.mjs test/flutter-clusters.test.mjs`; implement supported layout decoding and rerun, then run the explicit genuine feasibility script.
- [ ] Produce a go/no-go report with exact supported cluster/layout evidence, rejected controls and missing types. Two unsupported decoding iterations without a validated reference boundary stop expansion and leave N2 blocked for that profile until new source/evidence changes the condition.
- [ ] Commit `feat: validate a pinned Flutter snapshot profile` only for actual supported behavior; otherwise commit the documented experimental refusal and retain the unmet typed-recovery gate.

**Acceptance:** A typed object is identified by validated serialization and references, not printable token resemblance. Successful metadata identification alone does not unlock function recovery.

## Task N2: Flutter typed facts and native function attribution

**Files:** Create `src/frameworks/flutter/objects.ts`, `code-refs.ts`, `view.ts`; create `test/flutter-objects.test.mjs`, `test/flutter-code-handoff.test.mjs`; add `scripts/research/frameworks/qualify-flutter.mjs`.

**Consumes:** Successful N1 profile, R5 StaticFrameworkBridge and N0 NativeHandoff. **Produces:** `inspectFlutterProfile(source, selection, profile, context): Promise<FrameworkResult>` with typed object IDs, validated object-to-code relationships, selected function coordinates and separate raw provider evidence.

- [ ] Recover typed string/class/function/code relationships through supported references; preserve optimized-out, shared, unrecognized or stripped relationships as unknown. Code pointers must map to a unique executable range with correct instruction/source coordinates.
- [ ] Pass selected function seeds to the admitted existing REA/Ghidra provider on the matching supported host. Record decompiled/static observations separately from function identification and finite business answers. No new general instruction lifter/decompiler belongs here.
- [ ] Add failing controls for bait label outside a typed object, identical strings in different objects/functions, mismatched code pointer/ABI, shared/folded function bodies, stale provider evidence and known label with unknown business function.
- [ ] Build and run `node --test test/flutter-objects.test.mjs test/flutter-code-handoff.test.mjs`; implement selected profiles/views and rerun. Qualify at least three genuine seed/builds and two independent source shapes, including a structural holdout.
- [ ] Score label3 as a new exact typed task only if the independent judge confirms it; do not overwrite its previous unknown result. Commit `feat: link qualified Flutter objects to native function evidence`.

**Acceptance:** Typed objects, code attribution and selected business answers have separate statuses. Runtime recovery needs V5; native static evidence alone cannot establish app behavior.

## Task N3: Genuine Unity IL2CPP pair and method handoff

**Files:** Create `src/frameworks/unity/pair.ts`, `methods.ts`, `seeds.ts`; create `test/unity-pair.test.mjs`, `test/unity-handoff.test.mjs`; create `scripts/research/frameworks/qualify-unity.mjs`.

**Consumes:** N0 genuine pair/prerequisites, S1 source ranges and R5 StaticFrameworkBridge. **Produces:** `inspectUnityPair(metadataSource, binarySource, selection, profile, context): Promise<FrameworkResult>` and `prepareUnitySeeds(result, workspace, context): Promise<SeedReceipt>` only in an explicit write scope. Both inputs get independent full hashes; pair identity binds both and the profile. SeedReceipt is R5's verified startup-only seed contract; no nonexistent open_binary seed argument is assumed.

- [ ] Require an owned genuine same-build metadata/binary pair plus an independently built mismatched pair. Record Unity editor/version/platform/mode and provenance; if legitimate tooling/license/pair is absent, stop genuine qualification with an exact prerequisite record. A C++ stand-in tests pointer handling only.
- [ ] Reuse actual REA IL2CPP metadata/native linking and seed formats, including supported sublayout versions, registration candidates, relocations, generic-method limits and executable-pointer checks. Do not advertise all integer metadata versions as equivalent sublayouts.
- [ ] Add failures for swapped same-name/count pairs, duplicate tokens, multiple registration candidates, missing relocation, zero-backed pointer, overflow, folded bodies, unsupported packed relocations, wrong provider import base and generic unsupported sublayout. Structural consistency and same-build provenance remain separate.
- [ ] Build and run `node --test test/unity-pair.test.mjs test/unity-handoff.test.mjs`; implement bounded reuse/adapters and rerun. Seeds use exclusive generated files and complete hashes; unknown slots remain skipped with gaps.
- [ ] Qualify three fresh genuine builds covering branches, strings, shared/generic code and optimized/stripped variants. Score method-address linkage, decompilation and selected business answer separately. Commit `feat: qualify genuine IL2CPP method handoffs` only for observed support.

**Acceptance:** No genuine pair means genuine qualification stays blocked. A pair digest binds chosen files but does not cryptographically prove they were built together; ambiguity remains visible.

## Task N4: Android JNI declaration-to-code chain

**Files:** Create `src/frameworks/android/jni.ts`, `view.ts`; create `test/jni-handoff.test.mjs`, `test/jni-identity.test.mjs`; create `scripts/research/frameworks/qualify-jni.mjs`.

**Consumes:** N0 owned genuine Android toolchain/artifact, S1 native maps and R5 StaticFrameworkBridge with admitted REA/JADX/static provider. **Produces:** `inspectJniProfile(apkSource, selection, profile, context): Promise<FrameworkResult>` joining DEX `(class,method,descriptor)` to exact member occurrence/ABI/library digest and export/registration candidate/code range.

- [ ] Reuse the actual advertised REA JNI inspection, library and DEX views. Honor mangling/overload signatures; preserve per-occurrence identities when APK member names duplicate. A table-shaped record or JNI_OnLoad string does not prove registration was invoked.
- [ ] Add failures for overloaded signatures, wrong class, ABI mismatch, duplicate library names, wrong library export, table bait outside a call path, unresolved dynamic registration, unsupported relocation and ambiguous native address.
- [ ] Build and run `node --test test/jni-handoff.test.mjs test/jni-identity.test.mjs`; implement linkage/view and rerun. Export/native registration/class attribution are distinct facets, never merged into a presumed executed chain.
- [ ] Independently build three genuine APK/native bridge pairs using admitted legitimate tooling; recover selected native functions through REA/Ghidra and bind results back to the exact DEX declaration. No host library load, device install or live attach belongs to static qualification.
- [ ] Commit `feat: trace qualified JNI declarations to native code` with real scope/unsupported profiles recorded.

**Acceptance:** A source-bound declaration/library/code chain; candidate relationships remain candidate. Runtime RegisterNatives execution requires separate V5 evidence on a matching device/profile.

## Task N5: Genuine held-outs, capability wiring and support claims

**Files:** Modify product schema/service/worker/server/CLI only through the integrator; create `src/frameworks/view.ts`, `test/framework-api.test.mjs`, explicit `test/research/framework-recovery.test.mjs`, `scripts/research/qualify-frameworks.mjs`; update genuine-framework/native/coverage docs.

**Consumes:** N2-N4 implemented profiles, B3; V5 for any runtime facet. **Produces:** inspect_framework with strict profile-specific discriminated arguments: common path/profileId/collection/offset/limit, Unity additionally binaryPath, JNI/Flutter exact ABI/selection. No arbitrary provider command or export path is accepted.

- [ ] Write failing discovery/schema controls: unsupported/experimental profile, missing second Unity input, cross-root input, unknown ABI, wrong selected method, oversized page and no configured provider. Default static capability advertises only implemented admitted profiles with explicit qualification labels.
- [ ] Build and run `node --test test/framework-api.test.mjs`, implement dispatch/annotations and rerun; execute `npm test` to preserve existing APIs.
- [ ] Run each genuine three-way protected task through the independent judge on three fresh seed/builds, including stripped/optimized and benign equal-padding controls. Use artifact-only independent review; no expected labels/function addresses may be passed in from the private oracle as analyzer hints.
- [ ] Run `node scripts/research/qualify-frameworks.mjs --plan <frozen-plan.json> --workspace <owned-directory>` and the explicitly admitted provider suite. Missing profiles remain blocked/unavailable cells, not skipped successes. Genuine metadata, typed object, code and runtime facets stay separate.
- [ ] Apply B4/L2 gates and commit sanitized support/results as `test: publish qualified framework recovery profiles`.

**Acceptance:** Each advertised profile has real matching artifact/provider evidence and independent review. The full framework milestone is incomplete until Flutter, genuine IL2CPP and JNI gates all pass; partial releases say exactly which profiles remain unsupported.

# REA Orchestration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Automate the bounded original-analysis → justified inspection view → REA reanalysis workflow without treating handoff as proven recovery.

**Architecture:** An opt-in trusted profile launches one owned REA stdio MCP session with a fixed static-operation allowlist. A two-attempt controller links original/derivative evidence, preserves raw statuses and holds ownership through verified cleanup.

**Tech Stack:** Existing MCP SDK client, Node child_process without shell, Zod schemas, shared recovery store/policy and platform-specific owned-process supervision.

**Spec:** [Engineering design](../../specs/2026-10-30-comprehensive-recovery-design.md), sections 5, 6 and 8. Reuse [REA artifact reconstruction](https://github.com/morluto/rea/blob/c5f50e80d8032baba7c3f6af4b84f8ce2d49e65d/docs/javascript-artifact-reconstruction.md) and retained evidence rather than sending complete graphs back through MCP.

## Global Constraints

- Keep Node.js `>=24.16.0` for the existing product. Initial REA integration uses a separately admitted Node.js `24.22.1` runtime.
- Existing `anti-bla.result/1`, `status: ok|unknown|error`, CLI exits 0/3/2, and `behavioralEquivalence: unknown` remain compatible.
- Artifact content cannot select commands, profiles, packages, network destinations or judge rules.
- Integration requires trusted startup configuration and explicit workspace. Maximum 2 attempts; 30,000 ms total default, 120,000 ms trusted hard ceiling; 256 KiB incoming frame, 4 MiB retained projection and 100-page caps.
- Default product operations parse inert bytes only. No runtime-enabled REA operations enter this allowlist. No AI/co-author attribution in commits or release text.

## Review Focus

1. Fake `rea` executable/profile or target-controlled environment: fail admission before launch (R0).
2. SDK buffers an oversized frame before checking: enforce byte limit before concatenation/JSON parsing (R1).
3. Summary/route pages omit the callee/argument needed by the judge: handoff can complete, task confirmation remains unknown (R2).
4. Child spawns descendants or ignores cancellation: verify owned tree cleanup or quarantine the profile (R3).
5. Reanalysis repeats the same exhausted request or silently raises limits: two-attempt state machine forbids it (R2/R4).

## Task R0: Trusted REA profile and runtime identity

**Files:** Create `src/integrations/rea/profile.ts`, `contracts.ts`, `admission.ts`; create `test/rea-profile.test.mjs`, `test/rea-admission.test.mjs`; extend trusted startup options in `src/setup.ts` only after admission is implemented.

**Consumes:** F0 identity/policy. **Produces:** `ReaIntegrationConfig` with absolute owner-selected nodeExecutable/reaEntrypoint, expected hashes, upstream commit, supported schema digest, fixed environment allowlist, deadline/budgets and ownership backend; `admitReaProfile(config, context): Promise<AdmittedReaProfile>`.

Verify local regular files, expected runtime/version and wrapper/build manifest hashes without network or Git lookups during recovery. A package version is diagnostic, not a trust anchor. Config cannot be loaded from target-discovered manifests. Construct a minimum reviewed environment; clear target startup/provider/debug variables including NODE_OPTIONS/NODE_PATH. No package runner, shell snippet, fallback executable search or automatic install.

Freeze the minimum RequestOwner contract here: register owned child/start identity before work, observe child/tree state, cancel, and idempotent awaitable close returning released/incomplete/quarantined. R1 can use fake owners in portable tests; actual automatic integration remains disabled until R3 qualifies the real platform backend. R3 hardens this same contract instead of introducing a later incompatible owner.

- [ ] Add failing controls for wrong executable/entry hash, matching version with wrong build, target-relative profile, injected environment, symlink/device paths, unsupported runtime and absent process-ownership backend.
- [ ] Run `npm run build` and `node --test test/rea-profile.test.mjs test/rea-admission.test.mjs`; implement admission and rerun.
- [ ] Discover actual candidate pinned REA tool schemas in a controlled test; freeze the reviewed schema mapping for each supported source pin. Unsupported versions return typed compatibility evidence.
- [ ] Verify disabled profiles do not advertise recover_with_rea or imply target execution; commit `feat: admit trusted static REA integration profiles`.

**Acceptance:** Only explicitly trusted owner-selected tooling can launch. Missing ownership/schema/runtime prerequisites prevent automatic integration and leave manual inspection available.

## Task R1: Bounded owned stdio bridge

**Files:** Create `src/integrations/rea/bridge.ts`, `framing.ts`, `views.ts`, `process-owner.ts`; create `test/rea-bridge.test.mjs`, `test/rea-framing.test.mjs` and fake owned MCP server fixtures.

**Consumes:** R0 profile and F1 store. **Produces:** `openReaBridge(profile, owner, signal): Promise<ReaBridge>`; methods `analyzeApplication(selection): Promise<ReaObservation>`, `readView(reference, selection): Promise<ReaPage>`, `close(): Promise<CleanupReceipt>`. No generic tool or argv passthrough is public.

Use shell:false/windowsHide:true and fixed trusted arguments for the pinned source MCP entrypoint. Initialize/discover once; call only reviewed `analyze_javascript_application`, `inspect_analysis_view`, and bounded `get_evidence_bundle` summary recovery when the same session remains responsive. Adapter-generated snake_case parameters must match the discovered pinned schema. Preserve parent evidence IDs and raw provider status/coverage/limitations. Drain stderr concurrently with bounded bytes/hash; it is never protocol JSON or trusted instructions.

- [ ] Write failing server controls for split UTF-8/JSON lines, oversize before newline, 256 KiB exact boundary, deep JSON, unsolicited messages, missing ID, wrong schema, endless stderr, 101st page, total retained-byte limit and premature exit.
- [ ] Build and run `node --test test/rea-bridge.test.mjs test/rea-framing.test.mjs`; implement a verified bounded receive path around/beneath SDK transport and rerun. Checking size after SDK parsing is insufficient.
- [ ] Prove a page references the same owned session/parent; foreign/stale references cannot cause a new analysis. An unresponsive partial-evidence lookup consumes the existing deadline, not a new lease.
- [ ] Review framing/ownership and commit `feat: connect REA through a bounded owned MCP bridge`.

**Acceptance:** Exact wire/retention/deadline caps; no whole-graph request expansion; fake targets cannot select runtime tools. Semantic traces that are unpaged remain deferred or controlled-small-only, with explicit refusal for oversize.

## Task R2: Two-attempt recovery state machine

**Files:** Create `src/integrations/rea/recover.ts`, `classify.ts`, `task-evidence.ts`; create `test/rea-recovery.test.mjs`, `test/rea-task-evidence.test.mjs`.

**Consumes:** R1 bridge, J4 VerifiedProjectView and live trusted proof references. **Produces:** `recoverWithRea(request: RecoveryRequest, profile: AdmittedReaProfile, context: OperationContext): Promise<RecoveryRun>`. RecoveryRequest is `{path,entryModule,entryExport,resolutionMode,typeImportPolicy,featureId?}` with the same strict policy/selection types as ProjectRequest. Initial source kind is directory only; bare JS files/ASAR/ZIP return unsupported_source_kind. S2 later adds a separately qualified ASAR source variant. No generic artifact dispatch is implied.

`RecoveryRun` carries preparation complete/unknown, REA completed/partial/failed, selectedTask confirmed/unknown/incorrect, attempt records, source/view identities, selected evidence IDs, gaps and cleanup receipt. Outer `status` describes the bounded operation, not universal recovery. Classify actual resource/coverage/unanswered-task facts; choose one implemented countermeasure with changed input/selection. Never remove bytes based on a BLA name or repeat an identical exhausted call. Original analysis plus one justified derivative attempt is the total budget.

- [ ] Write failures for baseline already answers task, unrelated partial coverage, unrecognized resource code, no eligible proof, imported forged evidence, incomplete view, changed source, same request retry, third attempt and deadline consumed at startup.
- [ ] Add judge controls where REA exposes a route label but no exact callee/argument/source mapping. Handoff completion is recorded; selectedTask remains unknown. Do not infer fields that paged REA views do not supply.
- [ ] Build and run `node --test test/rea-recovery.test.mjs test/rea-task-evidence.test.mjs`; implement controller/classifier and rerun.
- [ ] Verify original raw failures and finite selected-task evidence survive in the final linked record. No aggregate claim overrides a facet's unknown.
- [ ] Commit `feat: automate bounded evidence-preserving REA recovery`.

**Acceptance:** A successful handoff and a confirmed task are separate, testable outcomes. Scope/limits never expand from an artifact directive or a failed attempt.

## Task R3: Cancellation, descendant ownership and quarantine

**Files:** Extend `process-owner.ts` and shared service ownership; create `test/rea-process-lifecycle.test.mjs`, `test/rea-cancellation.test.mjs`; create explicit real-platform tests under `test/research/rea-process-owner.test.mjs`.

**Consumes:** R2 ownership/state. **Produces:** Idempotent awaitable `RequestOwner.close(reason): Promise<CleanupReceipt>` with released/incomplete/quarantined state and live owned handles/start identities. POSIX own process groups and Windows kill-on-close Job Object or equivalently proven supervisor are separate adapters.

- [ ] Add owned helper processes for child/descendant spawn, close-during-startup, ignored TERM, held-open pipe, PID reuse simulation, simultaneous abort/exit and process creation after the caller's timeout. An unrelated control process must survive.
- [ ] On Windows, assign the process to the ownership boundary before admitting analysis work; do not claim a root PID exit proves descendant cleanup. If the required backend cannot be implemented/admitted, keep automatic integration disabled there and record the profile as unsupported.
- [ ] Build and run `node --test test/rea-process-lifecycle.test.mjs test/rea-cancellation.test.mjs`; implement cooperative close, 2,000 ms grace and owned termination/reap, then rerun.
- [ ] Real-platform controls must observe tree/handle release. Incomplete cleanup retains a lease and disables new recoveries for that profile; capability reads and manual static inspection remain available. No global kill-by-name command or blind PID kill is allowed.
- [ ] Independently review lifecycle races and commit `fix: retain REA ownership through cancellation and cleanup`.

**Acceptance:** No completed result after cancellation; no false clean idle state; cleanup failure is visible and recoverable through owned identity, without harming unrelated processes.

## Task R4: CLI/MCP integration and actual pinned REA qualification

**Files:** Modify `src/contracts.ts`, `src/service.ts`, `src/server.ts`, `src/cli.ts`, `src/setup.ts`, `skills/anti-bla/SKILL.md`, `scripts/plugin-mcp-launcher.mjs`; create `test/rea-integration-api.test.mjs`, `test/research/rea-recovery.test.mjs`, `scripts/test-integration.mjs`; add user guidance in `docs/RECOVERY.md`.

**Consumes:** R3 and F3. **Produces:** Advertised recover_with_rea only for a fully admitted configured profile; `npm run test:integration -- --profile rea-static` as a separately prerequisite-checked suite. Historical `test:research` keeps its existing meaning.

- [ ] Add failing discovery/annotation/setup controls for missing profile/workspace, configured static tool launch, dry-run setup, hostile caller IDs and CLI exits. A static tooling launch is disclosed distinctly from target execution.
- [ ] Build and run `node --test test/rea-integration-api.test.mjs test/mcp.test.mjs test/setup.test.mjs test/plugin.test.mjs`; implement startup/configuration and rerun.
- [ ] Run actual original-pin REA and the separately built reviewed second pin on JS/JSX/TS/TSX projects, large retained views, cancellation and unknown-task controls. Missing provider returns exit 2 with an exact prerequisite list; no mock may satisfy this gate.
- [ ] Run `npm test` plus the explicit admitted integration profile. Verify unchanged original hashes, complete sidecars, actual raw REA evidence, exact task mapping where available and observed cleanup.
- [ ] Clear independent Important/Critical findings and commit `feat: expose verified REA recovery workflows`.

**Acceptance:** Genuine same-session MCP/CLI workflows pass supported profiles. No confirmed task is inferred from transport success, and unsupported schema/platform profiles are absent or precisely unavailable.

## Task R5: Separately admitted static framework provider bridge

**Files:** Create `src/integrations/rea/framework-bridge.ts`, `framework-profile.ts`, `framework-evidence.ts`; create `test/rea-framework-bridge.test.mjs`, `test/rea-framework-seeds.test.mjs`, explicit `test/research/rea-framework-bridge.test.mjs`.

**Dependencies:** R4, S1 and N0. **Consumes:** R3 owned supervision, N0 admitted framework/profile/handoff types and S1 validated source coordinates. **Produces:** `openStaticFrameworkBridge(profile, owner, context): Promise<StaticFrameworkBridge>` with fixed methods `inspectDartAot({apk:AdmittedFile,abi})`, `inspectIl2cpp({metadata:AdmittedFile,binary:AdmittedFile,architecture?,genericInstances?})`, `inspectJni({apk:AdmittedFile,className?,methodNames?,descriptors?,abis?,libraryPaths?})`, `openNative(handoff:NativeHandoff):Promise<NativeSessionReceipt>`, `analyzeNativeFunction(session,handoff):Promise<RetainedReaObservation>`, `readView(parent,selection)` and `close()`. NativeSessionReceipt binds source SHA, owned generation, observed provider coordinate/base context and validated original mapping; parent references carry that generation. Define concrete bounded selections/results in framework-profile.ts from the actual admitted tool schemas; no generic callTool/argv passthrough exists.

The JS profile stays unchanged. A separately configured framework-static profile admits at most 16 fixed calls within its configured 30,000 ms default / 120,000 ms ceiling and existing frame/retained-byte limits. Candidate pinned mappings are inspect_dart_aot(path,abi,detail:summary), inspect_il2cpp_metadata(path,binary_path,binary_architecture?,generic_instances?,detail:summary), inspect_android_jni_bindings(path,class_name?,method_names?,descriptors?,abis?,library_paths?,detail:summary), open_binary(path,provider_id:ghidra), binary_overview, procedure_address(procedure,detail:summary), procedure_info(procedure), analyze_function(procedure:provider-canonical hex,detail:summary), close_binary and same-session inspect_analysis_view. Validate actual discovery/schema/pin before calling. Initial native admission **requires** the overview/canonicalization/info calls: open_binary alone supplies no observed import base or procedure address. If segments/image base are missing/conflicting or the handoff cannot be mapped to one provider function, return unknown. Never compute a provider coordinate from a guessed base. Unsupported providers without this contract are unavailable for native handoff.

- [ ] Write failing schema/authority tests for a runtime tool, unknown provider, foreign binary/session/reference, absent/conflicting overview base or segments, function not recognized by procedure_address/procedure_info, guessed procedure address, mismatched input hashes, unsupported version, unbounded native pseudocode and 17th call.
- [ ] Add native/Dart/IL2CPP/JNI view adapters for actual supported retained kinds/facets; preserve raw scope/coverage and producer receipts. Native decompilation is static provider output, not observed behavior.
- [ ] Define optional SeedReceipt `{path,sha256,inputIds,profileId,completion,producerReceiptId}`. ProducerReceipt must resolve to the admitted owned seed generator; a self-consistent external file/hash is unverified and cannot configure provider startup. If seeds are needed, verify before provider startup and use only the reviewed REA_GHIDRA_SEED_FILE trusted launch recipe. Never invent open_binary.seedFile or a remote environment-set tool. An extra owned provider session consumes the same deadline/call/cleanup budgets. Without a supported seed path, unknown function discovery remains unknown.
- [ ] Run `npm run build` and `node --test test/rea-framework-bridge.test.mjs test/rea-framework-seeds.test.mjs`, implement fixed adapters and rerun. Execute actual pinned native/IL2CPP/JNI schema controls only in the explicit provider suite; missing optional providers remain unavailable.
- [ ] Independently review process/seed/provider authority and commit `feat: compose bounded static framework providers`.

**Acceptance:** N2/N3/N4 have a real owned static integration surface without widening the JavaScript or runtime allowlists. No native-provider output is accepted without matching artifact/session/producer identity.

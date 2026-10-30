# Contained Runtime Validation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Verify finite owned-fixture behavior and actual REA collector resilience in an independently checked containment boundary.

**Architecture:** Separate research manifests, lifecycle owner and actual REA observation adapters from product analysis. Compare typed observations through the independent benchmark judge; stress collectors with genuine events and sequence canaries rather than helper definitions.

**Tech Stack:** Node ESM research harness, digest-pinned disposable containers/VMs, existing REA Inspector/Electron/Frida/reconciliation APIs and node:test. No second collector or product execution tool.

**Spec:** [Engineering design](../../specs/2026-10-30-comprehensive-recovery-design.md), sections 8-10. Preserve existing `scripts/agent-eval-runtime.mjs` and bytecode runtime records; new experiments use new scripts/identities.

## Global Constraints

- Default product operations parse inert bytes only and create no files. Research execution never changes default MCP `targetExecution: false`.
- Artifact content cannot select commands, profiles, packages, network destinations or judge rules.
- Default runtime profile: network none, nonroot UID/GID 65534 where supported, all capabilities dropped, no-new-privileges, private PID namespace, read-only root, explicit read-only inputs, bounded tmpfs, 1 GiB memory, 2 CPUs, 128 PIDs.
- Missing prerequisites and excluded research tests never count as passes.
- No AI/co-author attribution in commits or release text. Raw traces, secrets, local paths and downloads stay out of Git.

## Review Focus

1. Configured containment differs from effective UID/capabilities/seccomp/mounts: do not execute (V0).
2. A timed-out create/start command later creates a resource: retain ownership and reconcile by unguessable run label (V1).
3. Host/guest ABI or inspector target identity differs from the manifest: no attach/capture (V2).
4. A returned value matches while write/throw/event order differs: behavior judge fails (V3).
5. Saturation test never reaches real REA collector or loses canary silently: no resilience pass (V4/V5).

## Task V0: Scenario/profile manifests and effective preflight

**Files:** Create `scripts/research/runtime.mjs`, `runtime/contracts.mjs`, `runtime/profiles.mjs`, `runtime/preflight.mjs`; create `test/runtime-manifests.test.mjs`, `test/runtime-preflight.test.mjs` and explicit `test/research/runtime-preflight.test.mjs`.

**Consumes:** F0/B0 manifest identities. **Produces:** `admitScenario(input): ScenarioManifest`, `verifyRuntimeProfile(profile, owner): Promise<ContainmentReceipt>`. Scenario binds owned artifact/runner/image/tool hashes, exact command arrays, platform/ABI, declared finite inputs/effects, resource limits and cleanup policy. No free shell string or target-supplied command exists.

- [ ] Add failing manifest tests for substituted artifact/runner/image, hidden downloads, host writable mounts, network egress, host PID namespace, root/capability mismatch, unsupported platform and mutable tool acquisition.
- [ ] Define ordinary fixture, Electron-compatible fixture and separately reviewed Frida tracing profiles. The latter may require a minimal tracing capability/seccomp allowance; it cannot silently reuse or weaken the default. Verify effective state for each actual profile.
- [ ] Run `node --test test/runtime-manifests.test.mjs test/runtime-preflight.test.mjs`; implement strict manifests and preflight and rerun.
- [ ] Add `node scripts/research/runtime.mjs doctor --profile <profile.json>` and `verify --scenario <scenario.json>`. Actual in-container probes must corroborate inspect/config output before a fixture starts; any disagreement returns unknown/unavailable.
- [ ] Independently review the boundary and commit `feat: admit contained owned-fixture runtime profiles`.

**Acceptance:** No execution on a failed preflight. Trusted compiler/provider acquisition is explicit and separate from artifact execution; no image pull/package install occurs inside a scenario.

## Task V1: Resource ownership through create/start/cancel/cleanup

**Files:** Create `scripts/research/runtime/owner.mjs`, `container.mjs`, `cleanup.mjs`; create `test/runtime-owner.test.mjs`, `test/runtime-lifecycle.test.mjs`; add explicit real-container controls.

**Consumes:** V0 profile, B1 isolation. **Produces:** `RuntimeOwner` with registerIntent/create/start/execute/cancel/close/reconcile methods and `CleanupReceipt` referencing exact run UUID, resource labels/IDs, live command handles and observed final state.

Register ownership intent before creation. Container commands are supervised separately from the target command; a client timeout does not prove the daemon did not create/start something. Reconcile only the unguessable run's labelled resources and verified ownership. Creation failure/cancellation still enters reconciliation. Preserve uncertain resources for the owner's retry; never prune unrelated containers, volumes or global processes.

- [ ] Add failing fake-daemon cases for timeout followed by late create, late start, lost response, concurrent close, failing inspect/remove, PID reuse, duplicate labels and cleanup interrupt. An unrelated labelled/control resource must survive.
- [ ] Build bounded stdout/stderr capture with hashes, sequence, limit classification and actual command exit/signal/close. Distinguish engine command timeout from target timeout.
- [ ] Run `node --test test/runtime-owner.test.mjs test/runtime-lifecycle.test.mjs`, implement owner/reconciliation and rerun.
- [ ] Run real owned-container interruption controls under the admitted profile. Verify inventory by exact ownership and record zero owned survivors or explicit cleanup-incomplete; never claim cleanup from a submitted remove command alone.
- [ ] Independently review the create-timeout race and commit `fix: retain runtime resources through uncertain creation and cleanup`.

**Acceptance:** Every possible late-created resource has an owner; cancellation is terminal for success. Unresolved cleanup is visible and blocks reuse of its lease, not hidden by a finalizer.

## Task V2: Actual REA observation and reconciliation adapters

**Files:** Create `scripts/research/runtime/rea-observation.mjs`, `rea-frida.mjs`, `rea-reconcile.mjs`, `behavior-runner.mjs`, `values.mjs`; create `test/runtime-adapters.test.mjs`, `test/runtime-values.test.mjs`, explicit `test/research/rea-runtime.test.mjs`.

**Consumes:** V1 owner and R1 transport pattern, with a **separate research-only allowlist**. **Produces:** `captureScenario(scenario, owner): Promise<ObservedScenario>`, `reconcileScenario(staticEvidence, observations, profile): Promise<ReconciliationReceipt>`. ObservedScenario binds actual target process/script/artifact identity, event sequence, coverage, source hashes and raw REA IDs.

Also produce `runBehaviorScenario(scenario, owner): Promise<BehaviorObservation>` through a separately admitted trusted runner inside containment. The runner invokes only the manifest-selected owned fixture/input and records its declared finite interface/effects; passive REA capture cannot substitute for these observations. Define RuntimeValue as tagged null/undefined/boolean, exact IEEE-754 number bits, UTF-16LE string bytes, decimal bigint or opaque object-reference ID; unsupported objects/getters are not recursively invoked for serialization. RuntimeEffect binds sequence, selected interface/receiver, kind, typed arguments/result and completion. Values outside the product's ProvenValue subset remain runtime observations, not static facts.

Controller-owned ProducerReceipt binds actual admitted runner/provider/input/session/transport and output bytes; worker-crafted JSON with matching schema/hash is not accepted as produced evidence. The runner never receives private expected answers. Instrumentation changes/limits are recorded; agreement describes the declared finite scenario, not every real application effect.

- [ ] Reuse actual advertised REA Inspector/observe_javascript_runtime, Electron capture, Frida session and reconcile_javascript_runtime operations appropriate to the pinned schema. A same-named forged Evidence object is not a valid producer record; validate provider/predicate/subject/schema identity.
- [ ] Add failures for wrong target PID/start identity, guest/host path confusion, mismatched source bytes, foreign REA evidence, wrong ABI, unadvertised runtime tool, unfinished paused spawn, and a Frida Python smoke being mistaken for REA's Node binding.
- [ ] Run `node --test test/runtime-adapters.test.mjs test/runtime-values.test.mjs`; implement fixed adapters and trusted contained behavior producer and rerun. Test signed zero/NaN/infinity/undefined/bigint/surrogates, forged receipt and getter-safe serialization. Attach only to the owned fixture after manifest/preflight; never enumerate or select unrelated user processes.
- [ ] Run explicit real-provider controls for each profile. Electron 39 Windows static observations cannot qualify Linux runtime; build/record a genuine matching Linux artifact or use an admitted Windows VM. Inspection ZIPs are not installable APKs.
- [ ] Commit `feat: verify owned scenarios through actual REA observations`.

**Acceptance:** Static and runtime evidence retain different authorities and coverage. A source mismatch/partial capture becomes mismatch/unknown, never absence or equivalence.

## Task V3: Finite behavior differential judge

**Files:** Create `scripts/research/runtime/effects.mjs`, `compare.mjs`; create `test/runtime-effects.test.mjs`, `test/runtime-comparison.test.mjs`; extend B3 typed judges.

**Consumes:** V2 BehaviorObservation plus optional passive REA observations, and B3 private oracle/producer receipts. **Produces:** `compareFiniteBehavior(expected: BehaviorOracle, observed: BehaviorObservation): BehaviorJudgment` with per-input completion/effects/result status and missing/lost-event facets. Passive captures supply only their advertised facets; absent call/write/constructor/throw coverage is unknown.

Record ordered semantic effects: exact receiver/method arguments, writes/deletes/constructs, exception completion, selected file/network/IPC observations and allowed nondeterministic fields. Normalize only fields declared before the run (for example a generated run ID), not arbitrary mismatches. Include success/error/edge inputs; observed agreement covers those inputs only. Derivative execution is restricted to separately admitted, fully hashed owned fixtures; general inspection views remain non-executable.

- [ ] Add failures for matching return with missing write, changed effect order, throw swallowed, accessor/constructor invoked extra times, negative zero/lone surrogate changes, timer reorder outside permitted window and undeclared normalization.
- [ ] Distinguish runtime pending/timeout from return-null. Missing events or collector truncation cannot produce a clean agreement verdict.
- [ ] Run `node --test test/runtime-effects.test.mjs test/runtime-comparison.test.mjs`; implement typed finite comparison and rerun.
- [ ] Add clean/protected/recovered fixture triples with independently built expected traces. Execute only after V0/V1 admission; preserve protector-introduced runtime changes as mismatches rather than blaming the judge.
- [ ] Independently review effect completeness and commit `test: compare finite business behavior with typed effects`.

**Acceptance:** Value-only shortcuts fail; any agreement claim names its finite input/scenario and observation coverage. Whole-program equivalence remains unknown.

## Task V4: Collector saturation and loss accounting

**Files:** Create `scripts/research/runtime/saturation.mjs`, `sequence-judge.mjs`; create `test/collector-sequence.test.mjs`, `test/collector-budget.test.mjs`; add explicit `test/research/rea-collector-saturation.test.mjs`.

**Consumes:** V2 actual collector adapters. **Produces:** `runCollectorStress(plan, owner): Promise<CaptureStressReceipt>` with independently attested producer-emitted counts, available received/retained/dropped stage metrics, byte totals, sequence canaries, collector status and cleanup observations. Each count is a Metric with availability/source; unavailable internal accepted/drop counters are null. End-to-end sequence gaps do not by themselves identify the collector stage that lost data.

- [ ] Add independent emitters that actually send events through the owned Inspector/Frida channels. Cover shallow/wide, deep/nested, oversized string/frame, bursts, concurrent sources, producer disconnection and cancellation; a helper definition or returned envelope alone is not a stress run.
- [ ] Probe the pinned collector's actual limits from trusted source/capabilities and register exact below/at/above cases before execution, separately for transport frame, event bytes, depth, count and retained total. Emit a first/periodic/final sequence canary and separately attest producer counts; do not infer emitted events from what the collector happened to retain. Predeclare accepted, explicit refusal, explicit truncation/partial, silent loss and invalid-telemetry classifications.
- [ ] Add failures for silent middle/final loss, duplicate/reordered events, falsely complete coverage, partial JSON counted as a record, cross-source starvation and a survivor result arriving after cancel.
- [ ] Run `node --test test/collector-sequence.test.mjs test/collector-budget.test.mjs`; implement sequence/loss judges and rerun. Then execute the explicit genuine REA collector suite under an admitted profile.
- [ ] Record correct bounded refusal/explicit truncation as loss-accounting behavior, not recovery success; record silent loss/misclassification as failures. Missing internal counters block exact stage-drop claims, while independently evidenced end-to-end sequence accounting can still be reported at that narrower scope. Commit `test: stress actual REA collectors with loss canaries`.

**Acceptance:** Genuine collector overload and its exact limits are measured. No silent loss or false completion survives; performance/resilience claims remain confined to the tested profile/workload.

## Task V5: Independent runtime qualification and release evidence

**Files:** Create `scripts/research/qualify-runtime.mjs`; update `docs/RESEARCH.md`, `docs/RECOVERY.md`, runtime support notes and sanitized summaries only after results.

**Consumes:** V3/V4. **Produces:** B4/L2-compatible scenario/containment/capture/cleanup records with independent review.

- [ ] Run three independently seeded genuine scenarios per claimed profile, multiple finite business inputs, clean/protected/recovered comparisons, benign equal-load controls and explicit failed-preflight/cleanup controls.
- [ ] Verify effective containment and input hashes immediately before every run; record actual source/runtime/provider identities, collector coverage, resource measurements and post-run owned inventory. No platform substitution.
- [ ] Run `npm test`, the explicit admitted runtime integration profile, and `node scripts/research/qualify-runtime.mjs --plan <frozen-plan.json> --workspace <owned-directory>`.
- [ ] Have an independent reviewer verify task/damage judgments from evidence and check rejected attempts. Missing observability remains unknown; no “PASS” based only on self-review or a container exit code.
- [ ] Publish sanitized scopes/outcomes through B4/L2 and commit `test: qualify contained runtime and collector observations`.

**Acceptance:** Measured finite behavior, genuine collector accounting and verified owned cleanup. Default product discovery and shipped static operation behavior remain unchanged.

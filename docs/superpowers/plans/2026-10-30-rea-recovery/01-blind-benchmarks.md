# Blind Benchmarks Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Measure added recovery, correctness and resource use without leaked answers, weakened judges or omitted failures.

**Architecture:** A research-only controller generates sealed fixture capsules, exposes restricted tools to isolated worker lanes, journals every action, and invokes a separate typed judge after submissions close. Tool-only and fresh-agent experiments are distinct studies.

**Tech Stack:** Node ESM scripts, existing Zod/crypto/node:test, exact source-built BLA/REA, an explicitly admitted agent-provider adapter and optional disposable containers/VMs.

**Spec:** [Engineering design](../../specs/2026-10-30-comprehensive-recovery-design.md), sections 2, 4 and 10. Preserve the historical [agent protocol](../../../AGENT-EVALUATION-PROTOCOL.md) and its procedural-isolation limitation.

## Global Constraints

- Keep Node.js `>=24.16.0` for the existing product. Initial REA integration uses a separately admitted Node.js `24.22.1` runtime.
- Artifact content cannot select commands, profiles, packages, network destinations or judge rules.
- Missing prerequisites and excluded research tests never count as passes.
- No AI/co-author attribution in commits or release text. Private answers, seeds, raw traces and tool downloads stay out of Git.
- Default product operations parse inert bytes only and create no files. These research commands are not product MCP tools.

## Review Focus

1. Worker can reach host shell, another lane, clean counterpart or judge through an alternate tool: reject enforced-blindness claims (B1).
2. Low-entropy answer digest reveals the expected value: commit salted capsules rather than bare answer hashes (B0).
3. Correct string occurs at the wrong receiver/argument/function: judge rejects it (B3).
4. Failed/timeout trials disappear from averages or denominators: retain classifications and censoring (B2/B3).
5. Replayed artifacts or post-tuning pilot sets are called fresh held-outs: cohort and retirement rules block the claim (B4).

## Task B0: Manifest contracts, independent fixtures and oracle commitments

**Files:** Create `scripts/research/benchmark.mjs`, `scripts/research/bench/contracts.mjs`, `capsules.mjs`, `fixtures.mjs`, `judges.mjs`; create `test/benchmark-contracts.test.mjs`, `test/benchmark-fixtures.test.mjs` and public toy controls in `test/helpers/benchmark-fixtures.mjs`. Preserve existing `scripts/generate-agent-fixtures.mjs` and `scripts/judge-agent-evaluation.mjs` as historical harnesses.

**Consumes:** F0 identities/typed values/ProducerReceipt. **Produces:** Strict schemas `anti-bla.benchmark-plan/2`, `anti-bla.fixture-capsule/2`, `anti-bla.private-oracle/2`, `anti-bla.trial/2`. Reuse the common producer-receipt wire shape; do not invent a research-only incompatible authority type. Functions: `freezeBenchmarkPlan(input): FrozenPlan`, `buildFixtureCapsule(plan, fixtureSpec, builder): Promise<CapsuleReceipt>`, `commitPrivateOracle(oracle, salt): string`.

Frozen plans include tool/source/image/runtime pins, family allocation, paired lane rules, budgets, model requested/observed fields, stopping rules and judge revision. Capsules bind every artifact, runner, scenario and emitter output. Private oracles contain independent construction IR and typed expected observations; derive fixture/protector/order seeds through versioned HMAC namespaces. Record actual emitted/compiler hashes; determinism must be measured before claiming byte-identical replay.

- [ ] Write failing schemas/control tests: extra keys, plan mutation after freeze, swapped runner/artifact, wrong seed namespace, low-entropy unsalted commitment refusal, signed zero/lone-surrogate values, and nondeterministic compiler bytes correctly labelled as new artifacts.
- [ ] Create independent toy families for cross-module calls, receiver aliases and side effects. Literal expected toy answers validate the judge; held-out private answers are not imported by product tests or recognizers.
- [ ] Record the selected clean/protected relation as pending or independently validated in the capsule. B0 can complete with pending relations and does not depend on V0/V1. B4 must validate a claimed semantics-preserving relation before confirmatory trials, by an independent static proof or admitted contained observations. A changed/unknown relation is not an Anti recovery win; raw stored-byte tasks retain their narrower boundary.
- [ ] Run `npm run build` and `node --test test/benchmark-contracts.test.mjs test/benchmark-fixtures.test.mjs`, implement manifests/builders, then rerun.
- [ ] Freeze the initial cohort and judge allocation before J1/J2 tuning. Controller source-informed knowledge is recorded explicitly.
- [ ] Commit `test: define sealed recovery benchmark contracts`.

**Acceptance:** Every run can name exactly which frozen inputs/judge it used. Generator source/clean counterpart/private seeds are absent from worker capsules. Reproduction creates a new record rather than overwriting history.

## Task B1: Real lane isolation and provider admission

**Files:** Create `scripts/research/bench/isolation.mjs`, `broker.mjs`, `providers.mjs`, `doctor.mjs`; create `test/benchmark-isolation.test.mjs`, `test/benchmark-broker.test.mjs`; create explicit real-environment tests under `test/research/benchmark-isolation.test.mjs`.

**Consumes:** B0 capsule/plan. **Produces:** `admitAgentProvider(config): Promise<ProviderAdmission>`, `verifyLaneIsolation(plan, capsule, owner): Promise<IsolationReceipt>`, `runAgentCase(request, broker): Promise<AgentTrial>`. Define `AgentProvider` here: observed model metadata, restricted tool registry, submit/cancel/close methods and owner-only credential reference; credentials never enter tool results or worker containers.

Use a model/provider interface that exposes only the broker's allowed tools, or run the entire worker in an isolated VM. A normal collaboration subagent with unrestricted inherited host filesystem/shell tools cannot qualify enforced blindness. The broker accepts fixed commands/tool schemas, confines paths/mounts, disables egress from target execution, journals automatically, and has no oracle capability. Trusted model-provider networking is separate from target networking and must be recorded.

- [ ] Write failing broker tests for path traversal, symlink/mount escape, alternate API aliases, dynamic commands, target-supplied URLs, credential/environment reads and accessing another lane's capsule.
- [ ] Build an isolation probe that tries private oracle, clean counterpart, generator, other lane, host files and host process/service access. Every forbidden read must fail under actual OS/tool boundaries.
- [ ] Run `node --test test/benchmark-isolation.test.mjs test/benchmark-broker.test.mjs`; implement the broker/provider admission and rerun. Mock tests prove broker policy only.
- [ ] Implement `node scripts/research/benchmark.mjs verify-isolation --plan <plan.json> --workspace <owned-directory>`; real preflight absence returns exit 2 with `UNAVAILABLE`, never PASS. Unsupported agent-provider restrictions permit tool-only studies but block enforced-blind agent claims.
- [ ] Independently review the isolation boundary and commit `feat: isolate benchmark lanes from private judges`.

**Acceptance:** A negative-access receipt exists before any blind agent claim. No new paid API, login or credential is silently acquired; missing access is a concrete prerequisite, not fabricated telemetry.

## Task B2: Paired execution and honest resource meters

**Files:** Create `scripts/research/bench/runner.mjs`, `journal.mjs`, `metrics.mjs`; create `test/benchmark-runner.test.mjs`, `test/benchmark-metrics.test.mjs`.

**Consumes:** B1 provider/isolation and F2 operation adapters. **Produces:** `runPairedTrial(plan, capsule, owner): Promise<TrialSet>`, `Metric {value:number|null, unit, availability, source, reason?}`, append-only event journals with controller-assigned sequence numbers and hashes.

Lanes are clean-rea, protected-rea, protected-anti-rea. Keep models, observed settings, artifacts and ordinary inert tools identical except the declared Anti addition. Initial agent policy: 40 visible commands, 120 underlying analysis operations including nested orchestration, 600,000 ms recovery/submission deadline and 4 MiB cumulative returned tool text per trial. Separate cleanup budget is 10,000 ms with 2,000 ms cooperative grace; judge budget is 30,000 ms. Neither extends submission eligibility. Count/report startup, failed calls, views, retries, recovery, cleanup, judge and total elapsed separately. Randomize lane order using a precommitted schedule; fresh session per case/repetition. Only change these design values before cohort freeze.

- [ ] Write failing controls for swapped pair IDs, duplicate/reordered journal events, timeout after a partial answer, nested calls escaping counts, output quota, cancelled child, and provider exit without final submission.
- [ ] Test meters using owned known allocation processes on supported OSes; distinguish sampled process-tree RSS/interval/coverage, Linux cgroup memory.peak and Windows peak job commit. Include owned parent/worker/provider trees and mark missed/unknown descendants; no sampled value is called exact instantaneous peak RSS. Requested model/effort fields never populate observed fields without evidence.
- [ ] Run `node --test test/benchmark-runner.test.mjs test/benchmark-metrics.test.mjs`, implement run/meter primitives, then rerun. Missing tokens/cost/CPU/RSS remain null with availability reasons.
- [ ] Add `doctor`, `generate`, `run`, `judge`, `verify`, `export`, `replay` subcommands to the research CLI. Every write uses a new owned run directory; replay checks old hashes without rewriting them.
- [ ] Commit `feat: record paired recovery trials and measured resources`.

**Acceptance:** Timeouts/unknowns stay in the result set; the measured effort includes the entire recovery path. Provider absence and model access restrictions remain explicit.

## Task B3: Exact selected-task judges and public summaries

**Files:** Extend `scripts/research/bench/judges.mjs`; create `scoring.mjs`, `export.mjs`; create `test/benchmark-judges.test.mjs`, `test/benchmark-export.test.mjs`.

**Consumes:** B0 private oracle, B2 sealed submissions/evidence and controller-owned producer registry. **Produces:** `judgeTask(task, answer, evidence, oracle, receipts): Judgment`, where correctness is correct/incorrect/unknown/invalid-trial, and separate fields describe evidence validity, comparison eligibility, pairing and finite behavioral agreement. `summarizePairedTrials(trials): PublicSummary` emits all scheduled outcomes, eligible denominators, scope and metric availability.

Reuse F0's ProducerReceipt schema and F1's ProducerRegistry through the compiled shared module: admitted tool/runtime/input identities, owned invocation/session generation, output SHA-256, output coverage, exit/cleanup state and a controller-generated invocation ID. The broker/controller registers receipts from the actual owned transport; workers submit references, never authoritative producer fields or arbitrary evidence file paths. Digest/schema consistency alone cannot authenticate a worker-forged Evidence record. Missing/foreign/stale receipts invalidate the evidence; cross-artifact replay fails.

Call tasks bind exact entry/callee/receiver, argument index, source range and typed value. Effect tasks compare ordered calls/writes/constructs/deletes/throws and completion across finite declared inputs. Native tasks bind selected method/address and actual provider evidence. Format tasks compare exact selected bytes/digest and range. A provider `ok`, coincidental string, uninvoked helper or candidate address is insufficient. Evidence can support a completed subtask despite unrelated partial coverage; the relevant facet must be complete.

- [ ] Add independent negative mutations: wrong receiver, overload, argument, source digest, UTF-8/UTF-16 coordinate, sign of zero, throw order, dropped write, different artifact, stale evidence, forged self-consistent provider record/receipt, repeated artifact called a fresh seed.
- [ ] Run `node --test test/benchmark-judges.test.mjs test/benchmark-export.test.mjs`, implement literal typed predicates and immutable submission checks, then rerun.
- [ ] Export counts for every scheduled lane/classification, comparison eligibility and reasons, paired incremental outcomes, timeouts/censoring, fixture identities and metric availability. Only actual task/analysis budget or artifact-coverage unknown under a functioning admitted provider is eligible. Missing tools, failed isolation/meter/judge, unsupported host/runtime and uncertain cleanup remain reported ineligible records, never wins. Do not compute speedup from successes only; report descriptive results unless a registered statistical method and adequate data actually exist.
- [ ] Scan the export for raw local paths, credentials, private seeds, generator/oracle content and unrelated transcripts; include public input/evidence hashes and sanitized commands sufficient to understand the claim.
- [ ] Independently review the judges and commit `test: score recovery with independent typed evidence`.

**Acceptance:** All false-answer mutations fail. No exact answer is credited from an unrelated literal or an unverified source. Small cohorts are never represented as a universal bypass rate.

## Task B4: Freeze held-outs and apply milestone gates

**Files:** Create reviewed public cohort specifications under `docs/benchmarks/` and `scripts/research/bench/cohorts.mjs`; create `test/benchmark-gates.test.mjs`. Private generated manifests remain in ignored run storage.

**Consumes:** B3 and each milestone's completed implementation. **Produces:** `evaluateMilestoneGate(plan, trialSet): GateVerdict` with exact required/observed/blocked fields and report references.

- [ ] Register a pilot of two independent structural families × two seeds × three lanes = 12 fresh sessions. Use it to validate the harness; any fixes informed by it retire it from confirmatory evidence.
- [ ] Before running confirmatory agents, validate each claimed selected-task clean/protected relation independently. If finite execution is needed, V0/V1 are conditional gate prerequisites; do not run it on the host or make B0 wait on its downstream runtime tasks. Invalid/unknown relations remain reported ineligible records.
- [ ] Register v0.2 tool trials: three task families × three fresh seeds × four intensities = 36 protected cases, each paired with controls. Register v0.2 agent confirmation at fixed balanced intensity: three structural families × three fresh seeds × three lanes × two fresh repetitions = 54 sessions. A seed-level added-benefit verdict requires both repetitions' clean/Anti answers correct and both protected-only repetitions incorrect or eligible unknown; a baseline success in either repetition prevents that seed-level win. Report repetition outcomes as well as seed aggregation. Freeze task/time/output/model budgets and stopping rules before generation. Do not automatically schedule paid provider calls.
- [ ] Register the later broad agent allocation only when genuine profiles exist: six families × three seeds × three lanes × three repetitions = 162 sessions. This is a study configuration, not a power claim; retain unsupported cells and publish actual denominators.
- [ ] Require structural holdouts, not just new constants: unseen module/closure/receiver shapes, effect/exception paths, invoked versus uninvoked bait and artifact-aware carriers. Fixture author/judge review is separate from recognizer implementation; commitments precede answer exposure.
- [ ] Test gate mutations, including missing-provider unknown and mock/tool-only outcomes falsely submitted as agent wins. Run `node --test test/benchmark-gates.test.mjs`, and execute only the admitted explicit cohort. Apply the master plan's separate tool-benefit/fresh-agent three-independent-seed gates and no-confident-error controls. A failed gate is recorded honestly; never weaken the oracle after seeing outcomes.
- [ ] Commit public specifications and sanitized summaries as `test: publish scoped recovery benchmark results`; retain private evidence locally and mark exposed cohorts retired for future held-out claims.

**Acceptance:** Each milestone's claim maps to frozen, paired, source-bound outcomes and independent review. No extra model access, spending or genuine provider availability is assumed by this document.

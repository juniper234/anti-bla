# Foundation and Evidence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish compatible shared contracts, bounded retained evidence and lifecycle rules before the recovery workstreams add features.

**Architecture:** Add focused recovery types/policies and a bounded serialized-page store to the existing service. Keep current one-shot operations and pure parsers working. Validate new worker frames separately from the public result/MCP budgets.

**Tech Stack:** Existing TypeScript, Node.js, Zod, MCP SDK and node:test.

**Spec:** [Engineering design](../../specs/2026-10-30-comprehensive-recovery-design.md), especially sections 4-6. Task dependencies are in the [master plan](../2026-10-30-comprehensive-recovery.md).

## Global Constraints

- Keep Node.js `>=24.16.0` for the existing product. Initial REA integration uses a separately admitted Node.js `24.22.1` runtime.
- Existing `anti-bla.result/1`, `status: ok|unknown|error`, CLI exits 0/3/2, and `behavioralEquivalence: unknown` remain compatible.
- Default product operations parse inert bytes only and create no files.
- Missing prerequisites and excluded research tests never count as passes.
- Canonical design limits apply: 4 MiB/analysis, 16 MiB/service, 4 retained analyses, 600,000 ms TTL, 64 KiB internal frames and one active analysis.
- No AI/co-author attribution in commits or release text. Private raw evidence stays local.

## Review Focus

1. Extra worker frames after a seal, duplicate sequences or oversized JSON: reject without growing storage (F1).
2. Identical content under different module roles or ambiguous canonical paths: distinct IDs or explicit ambiguity (F0).
3. CLI process exit/TTL/LRU eviction: missing reference never triggers filesystem reads or recomputation (F2).
4. Cancellation between the last page and final seal: only validated partial records survive, with unknown coverage (F1/F3).
5. Fingerprinting misses a newly packaged parser or lifecycle releases busy state too early: fail compatibility checks (F3).

## Task F0: Capture baseline and freeze shared types/policy

**Files:** Create `src/recovery/contracts.ts`, `src/recovery/identity.ts`, `src/recovery/policy.ts`; create `test/recovery-contracts.test.mjs`, `test/recovery-identity.test.mjs`. Read existing `src/contracts.ts`, `src/service.ts`, `src/javascript.ts`, `src/artifacts.ts`, `src/sidecars.ts` and `test/service.test.mjs` before edits.

**Consumes:** Existing `Limits`, `RecordResult`, `SourceRange` and operation schemas. **Produces:** Design section 5 shared types plus `ProjectNode`, `ProjectEdge`, `ProjectFact`, `EffectSummary`, `ProjectAnalysis`, `StoredAnalysis`, `ProducerReceipt`, `OperationContext`. OperationContext owns signal, monotonic deadline, policy, roots, optional validated workspace and current lease; producers cannot extend deadlines. It is defined here because S0 consumes it immediately after F0.

Define `ProjectNode` as `{id,moduleId,kind,source?}` with closed kinds module/function/binding/call/effect/external. `ProjectEdge` has `{id,from,to,kind,authority,proofIds}` with closed kinds imports/calls/reads/writes/guards/returns. `ProjectFact` has `{id,source,rootId,kind,value,calleeId?,argumentIndex?,effect,assumptions,gapIds}`; kind is return/call-argument/predicate; value uses the design's `ProvenValue`; effect is pure/effectful/unknown. It must never encode unknown as null. `EffectSummary` records reads/writes/calls/constructs/deletes/throws/suspends and a completeness flag; lists contain IDs, not arbitrary source text. `ProjectAnalysis` binds schema, analysisId, inventory/entry/policy/tool identity, counts, coverage and gap IDs. `StoredAnalysis` binds this header to validated immutable collection pages and retained byte counts.

Functions: `canonicalRecordId(tag: string, fields: readonly string[]): string`, `analysisIdentity(input: AnalysisIdentityInput): string`, `parseRecoveryPolicy(input: unknown): RecoveryPolicy`. Use closed ASCII role tags and length-prefixed UTF-16LE string fields; sorted inventory, explicit omitted/null meanings and exact integer strings. Raw artifact hashes still hash raw bytes. Page offset/limit and retention/observation nonces are excluded from content identity; entry selection, source bytes, assumptions and policy are included. Add schema invariants for wholeSha256/hashCoverage, concrete RangeEvidence and stored-versus-decoded container coordinates.

- [ ] Run `npm test` unchanged and record the baseline count/exits; do not overwrite historical records or run the research suite implicitly.
- [ ] Add failing tests named `role_tags_cannot_be_impersonated`, `analysis_id_excludes_projection`, `analysis_id_binds_inventory_and_assumptions`, `unknown_is_not_null`, `strict_policy_rejects_unknown_keys`, `negative_zero_is_not_positive_zero`, `escaped_surrogates_preserve_code_units`. Assert equal IDs only for equivalent canonical inputs and changed IDs for each changed authority field; non-finite/undefined/BigInt/Symbol do not become false primitive facts.
- [ ] Run `npm run build` then `node --test test/recovery-contracts.test.mjs test/recovery-identity.test.mjs`; preserve the expected missing-module/schema failures before implementing.
- [ ] Implement the types, schemas and exact design profile constants; rerun the focused command. No operation is advertised yet.
- [ ] Review the type/dependency surface and commit `feat: define recovery evidence contracts`.

**Acceptance:** Stable role-safe IDs and strict schemas; current version/status/provenance tests remain unchanged. A design/type contradiction blocks downstream dispatch until resolved.

## Task F1: Bounded evidence store and worker delivery

**Files:** Create `src/recovery/store.ts`, `src/recovery/worker-protocol.ts`, `src/recovery/producers.ts`; modify existing `src/service.ts`, `src/analysis-worker.ts`; create `test/recovery-store.test.mjs`, `test/recovery-worker-protocol.test.mjs`, `test/recovery-producers.test.mjs` and an owned fake-worker fixture under `test/helpers/`.

**Consumes:** F0 records/policy. **Produces:** `AnalysisStore` with `begin(header): Lease`, `append(lease, page): void`, `seal(lease, outcome): AnalysisReference`, `read(source, collection, offset, limit): AnalysisPage`, `close(): void`; `validateWorkerFrame(value: unknown, state: WorkerDeliveryState): WorkerFrame`. AnalysisReference contains stable analysisId plus a random service-local retentionId; store lookup requires both. Separate services holding identical content still reject each other's retentionId.

Also produce ProducerRegistry with `beginInvocation(owner, toolIdentity, inputIds)`, `acceptOutput(invocation, bytes, coverage, outcome)` and `lookup(receiptId)`. Only the controller's owned transport can complete an invocation; IDs/fields supplied by a worker cannot register a producer. Test forged self-consistent records, foreign owners, stale generations, changed output and cross-artifact replay; research callers can reuse the compiled shared module without moving research functionality into MCP.

Store only schema-validated serialized pages; account headers, gaps, IDs, framing and pages before insertion. Each page records collection, stable record IDs and sequence. Start/page/seal messages are discriminated and capped at 64 KiB actual serialized bytes. Use an acknowledgement window of one page: the producer cannot queue an unbounded stream faster than parent validation/credit. Aggregation cannot exceed 4 MiB/analysis or 16 MiB/service. Evict LRU deterministically; enforce TTL using an injected monotonic clock. No AST/target Buffer graph, hidden disk cache or automatic recomputation.

- [ ] Add failing controls for the exact byte caps, fifth-entry LRU, 600,000 ms expiry, reads not refreshing absolute TTL, out-of-order/duplicate/post-seal frames, cyclic/unserializable payloads, foreign leases, and mutation of caller-owned objects after append.
- [ ] Add cancellation-before-seal controls: completed validated pages remain explicitly partial; unvalidated/source-unstable proofs are ineligible for handoff. Assert no fabricated complete count.
- [ ] Run `npm run build` and `node --test test/recovery-store.test.mjs test/recovery-worker-protocol.test.mjs` to observe failure, implement store/frame routing, then rerun to green.
- [ ] Run existing `test/service.test.mjs` and `test/mcp.test.mjs`; ensure legacy workers still use their supported bounded result route.
- [ ] Review accounting/lifetime independently and commit `feat: retain bounded recovery evidence pages`.

**Acceptance:** Exact counters prove bounded retention; malformed worker data cannot become public evidence; service close releases all leases. Cache eviction/expiry returns a typed unavailable result without source I/O.

## Task F2: Schemas, views and CLI/MCP lifetime

**Files:** Create `src/recovery/views.ts`; modify `src/contracts.ts`, `src/service.ts`, `src/server.ts`, `src/cli.ts`, `src/setup.ts`; create `test/recovery-views.test.mjs`, `test/recovery-api.test.mjs`; extend `test/mcp.test.mjs` and `test/setup.test.mjs`.

**Consumes:** F1 store, `AnalysisViewSource`. **Produces:** `readAnalysisView(store: AnalysisStore, request: AnalysisViewRequest, context: ReadContext): Promise<RecordResult>` and additive schemas for the planned operations. Implemented operations alone are advertised; schema stubs must not appear usable before their workstream lands.

Define AnalysisViewRequest as a strict discriminated union with source plus either `{kind:records,collection,offset,limit}` or `{kind:value-bytes,valueId,offset,length}` selection. ReadContext is the read-only projection of OperationContext with store/root/read-budget access and no producer-registration/write authority. Each string ProvenValue exposes its stable valueId and retained/not-retained availability; record projection cannot invent a retrievable body.

Collections are nodes/edges/facts/effects/gaps/modules/proofs/changes plus exact value bytes. Stable ordering is role-tagged record ID order within the sealed analysis; pages include exact total, returned count, next offset and coverage. Value selection uses valueId and even byte offset/length, with UTF-16LE encoding/code-unit length/digest, bounded to 4,096 returned bytes; proof/change records use ordinary pages. Omitted bodies stay in retained storage only when capacity was reserved. If exact value bytes cannot be retained within the shared cap, preserve the descriptor plus gap and return value_not_retained for byte reads; never reconstruct or imply availability. An evidence-file source requires explicit authorized path/SHA-256 and complete validation of J4's bounded anti-bla.analysis-export/1 schema. Imported records stay unverified imported evidence: hash/shape is not producer authenticity and cannot authorize writes or recovery. The one-shot project CLI computes then projects its selected section; it cannot consume a previous process's retained ID.

- [ ] Add failing parity/schema tests for extra keys, invalid selectors, foreign/expired reference, offset at/past end, stable page concatenation and 64 KiB default result refusal.
- [ ] Add a real MCP client test that creates an analysis, reads two pages in the same session, cancels one operation, and successfully reads a prior sealed page. A second service must reject the first service's reference.
- [ ] Add a one-shot CLI control proving a retained reference is not silently recomputed; a selected evidence-file digest mismatch returns error without trusting its contents.
- [ ] Build, run `node --test test/recovery-views.test.mjs test/recovery-api.test.mjs test/mcp.test.mjs test/setup.test.mjs`, implement the routing/projections, and rerun to green.
- [ ] Review public annotations/help and commit `feat: expose bounded recovery analysis views`.

**Acceptance:** CLI/API/MCP meanings agree; no placeholder capability, accidental write hint or filesystem side effect appears in the default service. Public wire budgets include escaping and caller-controlled request IDs.

## Task F3: Compatibility, cancellation and implementation identity

**Files:** Create `test/recovery-lifecycle.test.mjs`, `test/recovery-compatibility.test.mjs`; modify relevant service/worker identity helpers and `scripts/package-smoke.mjs` only where required. Add `docs/RECOVERY.md` as the user-facing shared-contract guide.

**Consumes:** F0-F2, including F0's OperationContext. **Produces:** Compatibility/lifecycle controls and tested ownership/counter behavior; do not introduce a second competing context type here.

- [ ] Write failing tests for timeout during frame delivery, simultaneous abort/worker exit, close during a queued page read, second analysis while worker termination is pending, and source identity invalidation before publication. Use barriers/fake clocks rather than fragile wall-clock sleeps.
- [ ] Assert the implementation fingerprint changes when a new compiled parser module changes; include all packaged own modules, not a manually incomplete list. Preserve the current 128-module fingerprint refusal until an explicit reviewed manifest/limit change is needed.
- [ ] Assert all existing operation response shapes, version-derived tests, exits and default `targetExecution:false` remain compatible. Do not assert an old fixed test count after new tests are added.
- [ ] Run `npm run build`, focused lifecycle/compatibility controls, then `npm test`; independently review the shared changes and document retention/privacy semantics.
- [ ] Commit `test: gate recovery lifecycle and compatibility` with actual test counts and the scoped review reference in local records.

**Acceptance:** A cancelled/failed operation cannot leak an active worker or claim a clean idle state before owned cleanup. All legacy regression assertions pass; new operations remain additive. No research/provider prerequisite has entered `npm test`.

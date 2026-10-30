# JavaScript Feature Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Recover selected entry-to-call/value/effect facts across modules while refusing unsound simplification and preserving exact evidence.

**Architecture:** Extend the current inert evaluator with conservative effect summaries, an authorized static module inventory, bounded interprocedural summaries and selected backward slices. Materialize only proven inspection changes in an exclusive multi-file view; pass it to REA through the separate orchestration plan.

**Tech Stack:** Existing Babel parser/traverse/types/generator, TypeScript, Node filesystem/crypto and node:test; no target execution or new general symbolic solver.

**Spec:** [Engineering design](../../specs/2026-10-30-comprehensive-recovery-design.md), sections 5-7. Read existing `src/javascript.ts`, `src/javascript/evaluator.ts`, `src/javascript/digest.ts`, `src/javascript-view.ts`, `src/sidecars.ts` and their regression tests first.

## Global Constraints

- Keep Node.js `>=24.16.0` for the existing product. Initial REA integration uses a separately admitted Node.js `24.22.1` runtime.
- Existing `anti-bla.result/1`, `status: ok|unknown|error`, CLI exits 0/3/2, and `behavioralEquivalence: unknown` remain compatible.
- Default product operations parse inert bytes only and create no files.
- Project policy: 64 modules, 16 MiB cumulative source, existing 8 MiB per-module JS admission, 8,192 nodes, 32,768 edges, 500,000 shared steps, 4 contexts/function and 8 SCC passes before widening.
- Missing prerequisites and excluded research tests never count as passes. No AI/co-author attribution in commits or release text.

## Review Focus

1. Known return value hides `new`, delete, throw, getters or coercion effects: preserve/refuse (J0/J2).
2. Imported value is read before cyclic initialization or after mutation: unknown, even when a fixed-point constant looks convenient (J1/J2).
3. A same-named method/parameter or noninvoked decoy matches the requested answer: exact binding/path evidence required (J3/J5).
4. Output flattens modules, rewrites loader semantics or imports outside the selected materialized closure: explicit gaps, no complete handoff (J4).
5. Signed zero, UTF-16 strings, exceptions or changed source are lost during proof/export: exact typed tests and invalidation (J0/J3/J4).

## Task J0: Conservative effects and value encoding

**Files:** Create `src/javascript/effects.ts`, `src/javascript/project/types.ts`; modify `src/javascript.ts`, `src/javascript/evaluator.ts` only as needed; create `test/javascript-effects.test.mjs`; extend existing normalization/review tests.

**Consumes:** F0 `EffectSummary`/`ProvenValue`. **Produces:** `summarizeEffects(node: t.Node, bindings: BindingContext, budget: WorkBudget): EffectSummary`, `canReplaceExpression(value: AbstractValue, effects: EffectSummary): boolean`. Define `BindingContext`/`WorkBudget` in `src/javascript/project/types.ts`; WorkBudget exposes shared `charge(kind, amount)` and `checkpoint()` and cannot reset per module. Define `AbstractValue` as constant/known-int32/allocation/unknown with proof/effect references; constant carries a `ProvenValue`, not a coerced JSON value.

- [ ] Add failing literal cases for constructor side effects returning constants, delete on ordinary/proxy candidates, throw after/before a write, accessors, `Symbol.toPrimitive`, shadowed intrinsics, await/yield, direct/indirect eval, with, non-finite numbers and negative zero. Assert exact source effects or explicit unknown; no host marker file is ever created.
- [ ] Preserve current independently reviewed intrinsic/digest assumptions; a value known on normal completion does not prove termination or purity. Ordinary allocation identity/escape remains distinct from a primitive fact.
- [ ] Run `npm run build` and `node --test test/javascript-effects.test.mjs test/javascript-normalize.test.mjs test/javascript-review-round1.test.mjs`; implement conservative accounting and rerun.
- [ ] Verify every rewrite is blocked by an unresolved effect; unmodified source remains available with hashes and reason codes.
- [ ] Independently review and commit `fix: preserve effects in JavaScript recovery proofs`.

**Acceptance:** No constructor/delete/throw/coercion counterexample becomes a pure replacement. Old single-file API claims remain their original bounded scope.

## Task J1: Authorized project inventory and static resolution

**Files:** Modify J0's `src/javascript/project/types.ts`; create `src/javascript/project/inventory.ts`, `resolve.ts`, `snapshot.ts`; create `test/javascript-project-resolution.test.mjs`, `test/javascript-project-identity.test.mjs`.

**Consumes:** F1 identities/store, J0 budget/bindings and existing root admission. **Produces:** `acquireJavaScriptProject(request: ProjectRequest, context: OperationContext): Promise<ProjectSnapshot>` and `resolveStaticDependency(from: ModuleSnapshot, specifier: string, inventory: ProjectInventory): Resolution`.

`ProjectRequest` contains directory path, entryModule, entryExport, resolutionMode (node-esm/node-cjs) and typeImportPolicy (conservative/ts-verbatim/ts-remove); defaults are mode inferred only from unambiguous extension/package type and conservative type imports. Ambiguous mode is a gap. `ProjectSnapshot` contains bounded fully hashed module bytes/loader/relative path plus acquisition gaps. Worker-private bytes/ASTs are never stored in the parent. First support exact relative ESM paths, named/default/local re-exports and literal CommonJS require/exports. Native ESM requires exact file specifiers; CJS legacy extensionless resolution probes only .js/.json/.node under the declared Node policy, with JSON/native content external to JS value proofs. No .ts/.tsx substitution or bundler probing is assumed. Read bounded inert package type only; do not execute package exports/hooks or search node_modules. Nonrelative/dynamic imports remain external gaps.

Distinguish whole-declaration `import type` from `import { type T }`: the latter can preserve a side-effect import under verbatimModuleSyntax. Erase only when the declared matching policy proves it; conservative mode retains a possible runtime dependency/initialization barrier. Policy binds evidence identity and cannot be inferred from a convenient expected answer. TS/JSX syntax parsing is not proof of a particular emitted runtime module graph.

- [ ] Add independent fixtures for two/three-file exports, shadowed require, default/namespace aliases, duplicate star exports, cyclic initialization, dynamic imports, missing modules and builtin/package imports. Test ESM extensionless refusal, distinct CJS probes, inline type-only side-effect imports under verbatim/conservative modes and whole-declaration type imports. Initially refuse star-export value proofs unless the unique binding is proven.
- [ ] Add path controls for escape, symlink/junction, case collision, Unicode spelling, reserved output names, deep trees, unrelated giant files and changed source. Traverse only the selected dependency closure in deterministic order, under the shared counters.
- [ ] Run `npm run build` and `node --test test/javascript-project-resolution.test.mjs test/javascript-project-identity.test.mjs` to observe failure; implement inventory/resolution/snapshots and rerun.
- [ ] Assert exact per-module hashes and entry identity; inventory truncation preserves named gaps and cannot claim complete closure. No source import or target getter runs.
- [ ] Commit `feat: inventory bounded JavaScript dependency closures`.

**Acceptance:** Resolution is explicit, reproducible and root-confined. Package metadata or a target string cannot select a tool/configuration or trigger acquisition.

## Task J2: Interprocedural summaries and bounded graph

**Files:** Create `src/javascript/project/summaries.ts`, `graph.ts`, `fixed-point.ts`; adapt evaluator integration; create `test/javascript-project-summaries.test.mjs`, `test/javascript-project-budgets.test.mjs`.

**Consumes:** J1 snapshot and J0 effects. **Produces:** `analyzeJavaScriptProject(snapshot: ProjectSnapshot, request: ProjectRequest, budget: WorkBudget): ProjectAnalysisRecords`; `FunctionSummary {functionId,contextKey,normalReturn,effects,dependencyIds,initialization,termination}`. Termination remains unknown initially. `ProjectAnalysisRecords` is the worker-private typed header/collections that F1 seals.

Implement parameterized summaries for a documented pure subset: primitive arithmetic/bitwise/boolean operations, statically bound calls, exact primitive arguments, immutable scalar closures and conservative own-object nonescaping properties. ContextKey binds abstract arguments, captured immutable values, initialization assumptions and call string length 1; max 4 contexts/function. Parameterized summaries must be soundly instantiated/joined for every call. The fifth distinct context widens to unknown; f(1) cannot seed a cached constant for f(2). SCC worklist runs at most 8 passes and widens remaining values/effects to unknown; never unroll recursion or expand Cartesian string/alias products. Top-level initialization and ESM live-binding/cycle barriers remain visible. The existing digest template stays narrow; add no name-based recognizer authority.

- [ ] Add failing tests for imported helper `f(x)=x*3+7` returning exact finite values, two arguments/captures at the same call string, fifth-context widening, aliases to different helpers, closure capture mutation, recursive SCCs, getter dispatch, prototype mutation, shadowed exports, conditional throws and initialization-before-read.
- [ ] Add exact cap tests at 64 modules, 8,192 nodes, 32,768 edges, 4 contexts and the shared 500,000-step boundary. The first refused expansion has a gap; no per-module reset bypasses the cap.
- [ ] Build and run `node --test test/javascript-project-summaries.test.mjs test/javascript-project-budgets.test.mjs`; implement summaries/graph and rerun.
- [ ] Validate deterministic IDs and bounded serialized pages across traversal orders; preserve independently valid local facts when unrelated graph coverage is partial.
- [ ] Obtain fresh semantic review and commit `feat: prove bounded cross-module JavaScript facts`.

**Acceptance:** Correct binding/source-specific facts on the supported subset; dynamic/effect/initialization ambiguity remains unknown. Full program semantics and termination are not inferred.

## Task J3: Feature-directed slices and safe project normalization

**Files:** Create `src/javascript/project/slice.ts`, `proofs.ts`, `normalize.ts`, `views.ts`; create `test/javascript-project-slices.test.mjs`, `test/javascript-project-normalize.test.mjs`; wire the implemented project inspection through F2.

**Consumes:** J2 records/proofs and F1/F2 views. **Produces:** `traceProjectFeature(analysis, selector: FeatureSelector, budget): FeatureSlice`; `normalizeJavaScriptProject(snapshot, analysis, selection): ProjectNormalization`, whose changes bind original module/range, replacement bytes, proof IDs and assumptions.

Follow bindings/control/data dependencies from the selected root to a selected call argument/return/effect. Classify observed/proven/candidate/unknown edges separately. A false guard is removable only under an actual proof with all evaluation effects preserved. Normalization changes pure expressions only; retain unrelated definitions, corpus/self-hash inputs and effectful statements. Long values use exact bounded retrieval, not an unlabeled preview. Unsupported proof serialization is unknown.

- [ ] Add failures where the right literal appears in a decoy, wrong receiver/argument/export, computed property with a getter, dynamic function reassignment, try/finally path, source self-hash or reflection. Check exact selected source/callee/argument and the preserved effect order.
- [ ] Add round-trip tests for negative zero, UTF-8 source byte versus UTF-16 parser ranges, escaped surrogate code units, TS/JSX loaders and changed inventory. Stored IDs must bind assumptions and source bytes.
- [ ] Build and run `node --test test/javascript-project-slices.test.mjs test/javascript-project-normalize.test.mjs`; implement selected slices and normalization and rerun.
- [ ] Exercise real MCP bounded views with oversized benign graphs: complete retained records remain accessible in pages while public replies obey the output/frame cap.
- [ ] Commit `feat: expose source-bound feature slices and inspection changes`.

**Acceptance:** Every emitted change has a live own-analysis proof and a complete change map. A correct-looking value without the selected binding/path is not a recovered task.

## Task J4: Exclusive multi-file inspection export

**Files:** Create `src/javascript/project/sidecars.ts`; reuse/refactor shared private helpers from existing `src/sidecars.ts` without weakening them; create `test/project-sidecar.test.mjs`, `test/project-sidecar-loaders.test.mjs`, `test/project-sidecar-interruption.test.mjs`.

**Consumes:** J3 snapshot/normalization, configured `WorkspaceIdentity`, F2 wire preflight. **Produces:** `prepareJavaScriptProjectView(snapshot, normalization, workspace, context): Promise<ProjectViewReceipt>`, `verifyProjectView(receipt, workspace, context): Promise<VerifiedProjectView>`, and `exportAnalysisEvidence(reference, store, workspace, context): Promise<AnalysisExportReceipt>` exposed as export_analysis_evidence only with an explicit workspace.

Use one exclusive transaction directory containing fixed `application/`, `changes.json` or bounded change pages, and final `project-evidence.json`. Preserve validated safe relative source paths/loaders under application, retaining internal relative imports; reject case collisions/reserved names/links/escaping paths rather than inventing a remapping. Only admitted closure files and bounded generated package type/entry metadata are materialized; never copy hooks or unrelated target files. New project limits: 16 MiB derivative total, 8 MiB/file, 128 managed entries including directories/manifests, depth 16, 240 UTF-16 units/segment, 64 KiB final manifest and 4 MiB total change/evidence pages. Exceeding these limits is unknown, not a partially complete export.

Evidence export is a separate exclusive transaction containing final analysis-evidence.json with schema anti-bla.analysis-export/1, header, complete retained collections, exact available value bytes, producer identity and recorded gaps. Total sealed file ≤4 MiB. It has no live retention capability, raw AST or private host path. Return its path/bytes/SHA-256 only after fsync/rehash/evidence-last completion. CLI `export-analysis-evidence` can export a selected one-shot project analysis during that same process, or a live service reference in MCP; it cannot resurrect an expired ID. Re-import verifies bytes/schema but labels producer authority unverified; fresh own-analysis proofs are required before using it for a write/handoff.

- [ ] Add failing tests for exclusive collisions, workspace parent change, junctions, short writes, fsync/rehash mismatch, cancellation at every file/manifest boundary, output preflight failure and original changes between analysis/export/startup.
- [ ] Add actual JS/JSX/TS/TSX multi-file REA parsing controls using explicit integration tests after R1; portable tests verify filenames, bytes, import closure and hashes without requiring REA.
- [ ] Run `npm run build` and `node --test test/project-sidecar.test.mjs test/project-sidecar-loaders.test.mjs test/project-sidecar-interruption.test.mjs`; implement exclusive evidence-last writes, then rerun.
- [ ] Verify every emitted file before final evidence and again before handoff. Imported arbitrary evidence files cannot authorize a rewrite; require the current trusted analysis/proofs. Lost responses/locks/partial directories remain uncertain and retained.
- [ ] Review filesystem/security behavior independently and commit `feat: export verified multi-file inspection views`.

**Acceptance:** Originals are unchanged; loader/import identity and all changes are recorded. Only complete successful response plus matching receipt/bytes and released **view-write transaction** ownership can authorize static REA handoff. The encompassing request/analysis lease remains held through REA cleanup. Inspection files are never executed.

## Task J5: Protected and held-out qualification

**Files:** Create `scripts/research/qualify-javascript-project.mjs`, `test/research/javascript-project.test.mjs`; update `docs/JAVASCRIPT.md`, `docs/COVERAGE.md`, `docs/RECOVERY.md` only after observations exist.

**Consumes:** J4, R4 and B3. **Produces:** New immutable qualification records and B4-compatible exact selected-task evidence; no rewrite of prior C3/C7 results.

- [ ] Verify exact pinned public BLA emitters and rebuilt REA identities; use owned fixtures with at least three structural task families, three fresh seeds and four actual intensities. Preserve real emitter failures/unsupported transformations.
- [ ] Run clean+REA, protected+REA and protected+Anti+REA with identical budgets; score exact selected values/effects/source bindings using the independent judge. Contained behavior checks, when used, follow V0/V1 and cannot run on the host.
- [ ] Run the registered held-out agent cohort only after B1 isolation and provider admission. If those prerequisites are unavailable, report tool-level results and leave the agent-benefit gate unqualified.
- [ ] Run `npm test`, then `node scripts/research/qualify-javascript-project.mjs --plan <frozen-plan.json> --workspace <owned-directory>` and explicit integration suite. Obtain independent artifact-only evidence review and clear Important/Critical semantic findings.
- [ ] Publish the whole cohort's sanitized outcomes through B4/L2. Commit `test: qualify scoped cross-module recovery` only with actual scope/results; if the incremental gate fails, retain the failure and keep the milestone objective open.

**Acceptance:** No hidden answer access, no string-only success, no unjustified equivalence claim. Three independent held-out seeds in a predeclared family must satisfy the master's incremental gate before claiming a new recovery benefit.

# Comprehensive REA recovery design

Date: 2026-10-30. Status: proposed implementation specification, approved in direction by the operator's request to plan all six priorities. All new capabilities remain unimplemented until their task and release gates pass.

## 1. Goal and acceptance boundary

Build an evidence-preserving companion that helps REA recover selected real application features from BLA-protected artifacts within declared resource budgets. Implement all six workstreams: deeper JavaScript semantics, automatic REA handoff, streaming format inspection, contained behavioral verification, compiled-framework recovery, and independent benchmarks.

A capability is complete only when its implementation, adversarial tests, genuine-provider qualification where applicable, independent review and public documentation agree. An `ok` parser response is not a feature-recovery result. A release can ship a narrower qualified support matrix; the whole roadmap cannot be called complete while a required profile is blocked or unqualified.

Non-goals: universal deobfuscation, restoring genuinely discarded information without another evidence source, a replacement for REA or a new general decompiler, changing BLA, publishing unsupported bypass percentages, host execution of artifacts, or automatic global client registration. No ICE/Greenhouse changes belong to this project.

## 2. Observed baseline and source authority

- Starting Anti-BLA source: `75d18499c2fd3ec197301c449c9eb7e07eaaa818`; package/runtime version `0.1.0`; immutable published tag `v0.1` points to the earlier release commit. Planning changes do not move that tag.
- Existing implementation: TypeScript ES modules, strict NodeNext compilation, Babel static parsing, Zod contracts, MCP SDK, one active analysis worker, explicit roots and optional exclusive sidecar workspace. Tests are under `test/`, not `tests/`.
- Public baseline: 326 portable tests; 22 separately opted-in historical research tests. The earlier complete local workspace's 348 tests are a different evidence record.
- BLA qualification pin: `b2d643600774d62e562081129e55b13b0d9e8a80`, version 1.5.1. REA qualification pin: `317bf3fe235e655b2d752d3be261cc0da7d00f2b`, version 6.8.0.
- A newer reviewed REA documentation/source point is `c5f50e80d8032baba7c3f6af4b84f8ce2d49e65d`, also declaring 6.8.0. Version strings alone are insufficient compatibility identities. It is a candidate second test pin, not an automatic replacement for the historical baseline.
- Current JS proofs are per-file, mostly primitive values/known bits plus a narrowly verified digest structure. Current sidecars contain one inspection file. `readSnapshot` buffers and hashes the complete input; native/model adapters impose additional caps.
- Genuine Electron observations distinguish real fuses from appended bait, but establish no runtime enforcement bypass. Genuine Flutter snapshot metadata is 3/3; exact typed labels are 2/3; business-code recovery remains unknown. No qualified genuine Unity IL2CPP pair exists yet.
- All three prior fresh-agent lanes answered their selected tasks. There is no demonstrated incremental agent win, general equivalence result or measured token/cost advantage.

Authority order: this design's shared contracts; the workstream plan for implementation detail; actual source and tests for existing behavior; historical reports for historical observations. Resolve contradictions before coding. New measurements get new records rather than editing old outcomes.

Primary upstream references: [BLA implementation pin](https://github.com/qybaihe/bla/tree/b2d643600774d62e562081129e55b13b0d9e8a80), [REA original qualification pin](https://github.com/morluto/rea/tree/317bf3fe235e655b2d752d3be261cc0da7d00f2b), [REA artifact reconstruction](https://github.com/morluto/rea/blob/c5f50e80d8032baba7c3f6af4b84f8ce2d49e65d/docs/javascript-artifact-reconstruction.md), [REA runtime reconciliation](https://github.com/morluto/rea/blob/c5f50e80d8032baba7c3f6af4b84f8ce2d49e65d/docs/javascript-runtime-reconciliation.md), [REA Flutter inspection](https://github.com/morluto/rea/blob/c5f50e80d8032baba7c3f6af4b84f8ce2d49e65d/docs/flutter-analysis.md). Read implementation, not upstream BLA tests/challenge answers, for new source-informed research.

## 3. Chosen architecture and alternatives

Keep Anti-BLA as a companion with narrow, versioned operations. Reuse REA's application graph, selected-source analysis, retained evidence, tracing, native providers and reconciliation. Add proof-producing project analysis and an optional integration controller around those interfaces. Keep runtime experiments in a separate harness that is absent from default MCP discovery.

Alternatives considered:

| Approach | Benefit | Cost / reason not chosen as the default |
| --- | --- | --- |
| Fork REA and rewrite its limits/providers | Direct access to internals | Large maintenance surface and duplicated upstream work; unnecessary for initial supported workflows |
| Increase limits and remove recognizable BLA markers | Quick demonstration | Does not establish reachability, can discard real behavior, and scales poorly against fresh decoys |
| Companion with bounded proofs and explicit REA integration | Preserves upstream compatibility, source identities and selective recovery | Requires stable contracts, transport/lifecycle handling and rigorous qualification; chosen |

A future upstream contribution can replace an adapter after equivalent tests pass. This plan does not send patches to someone else's repository.

## 4. Trust and compatibility rules

1. Artifact text, paths, metadata, diagnostics, comments and embedded URLs are untrusted data. They cannot select commands, profiles, packages, network destinations or judge rules.
2. Preserve originals. Default product operations parse inert bytes only and create no files. Inspection exports require an explicitly configured existing workspace, exclusive tool-owned children, source/change identities and completion evidence written last.
3. Existing `anti-bla.result/1`, `status: ok|unknown|error`, CLI exits 0/3/2, and `behavioralEquivalence: unknown` remain compatible. Add structured subrecords, operations and declared profiles; do not silently reinterpret old fields.
4. Distinguish observed bytes, proven static facts, candidate relationships, runtime observations and unknowns. Runtime agreement is finite observed agreement, never whole-program equivalence.
5. Inputs outside supported syntax, layouts, ownership, budget or providers return explicit gaps/refusals. Missing prerequisites and excluded research tests never count as passes.
6. Tool/runtime/provider identities include executable/source hashes, exact versions, schemas and effective limits. Do not trust a binary merely because its basename is `rea`.
7. Keep Node.js `>=24.16.0` for the existing product. Initial REA integration uses a separately admitted Node.js `24.22.1` runtime. Do not raise the floor or install dependencies through target manifests.
8. Keep dependency versions locked. Prefer existing Node/Babel/MCP/Zod capabilities. Any additional parser/provider dependency gets source/license/integrity review and lockfile changes in its owning task.
9. A native Windows process and a Linux container are different environments. A Linux execution cannot qualify a Windows Electron EXE. Unsupported platforms stay explicit.
10. No AI/co-author attribution in commits or release text. Publish only reviewed source, sanitized result summaries and verified release artifacts; retain private paths, raw traces, secrets and tool downloads locally.

## 5. Canonical interfaces

New shared modules live in `src/recovery/`; format readers live in `src/io/` and their format directory. Research-only controllers live under `scripts/research/` and do not become product exports. Paths below are planned files unless explicitly identified as existing.

### 5.1 Product operations

| Operation | Inputs and availability | Output responsibility |
| --- | --- | --- |
| `inspect_javascript_project` | Directory `path`, `entryModule`, `entryExport`, declared resolution/type-import policy, optional section/offset/limit; default static capability | Module identities, selected-root graph, proven facts, effect summaries and explicit gaps |
| `read_analysis_view` | `source` is a same-service retained reference or an explicitly selected sealed evidence file; collection, offset, limit | Stable bounded pages; never rerun a missing analysis |
| `prepare_javascript_project_view` | Project selection plus explicit configured workspace | Exclusive multi-file inspection view, change map and evidence-last completion manifest |
| `export_analysis_evidence` | Selected one-shot project analysis or live service reference plus configured workspace | Bounded sealed evidence file for explicit durable import; import alone grants no producer authority |
| `recover_with_rea` | Initially directory project selection and optional selected feature ID; requires configured trusted REA profile and workspace; ASAR support is added only after S2 | At most two bounded attempts with original/derivative linkage and raw REA status/coverage retained |
| Existing format operations | Existing arguments remain valid; trusted service option `ioProfile: streaming-v1` opts into new I/O | Add format-specific range evidence without changing old buffered defaults |
| `inspect_bun` / `read_bun_entry` | Explicit path, occurrence moduleIndex for entry reads, bounded offset/limit or length; implemented and wired by S3 | Validated executable-contained graph and exact stored selected bytes; independent of later framework routing |
| `inspect_bplist` | Explicit path, optional node/page selection, `allowPrefixCandidate` boolean default false; only after format qualification | Validated original graph or conditional prefix candidate, never silent repair |
| `inspect_framework` | Explicit path, `profileId`, optional selected fact/function/binding; capability advertised only for admitted static profiles | Version-bound typed objects, code locations and relationships; unavailable providers/layouts remain unknown |

CLI exposes hyphenated operation names. Project inspection accepts `--entry-module`, `--entry-export`, `--section`, `--offset`, `--limit`. Trusted startup options, not artifact tool arguments, select `--rea-profile` and `--io-profile`. A one-shot CLI may compute then project a page; a retained reference works only inside its original long-lived service. Cross-process reuse requires an explicit sealed evidence export and `--evidence-file` plus its expected SHA-256.

### 5.2 Shared types

Define these once in `src/recovery/contracts.ts`; workstreams import rather than redeclare them:

```ts
type ByteRange = { offset: string; length: string }; // canonical unsigned decimal
type SourceIdentity = {
  fileBytes: string; wholeSha256: string | null;
  hashCoverage: 'whole-file' | 'selected-ranges' | 'none';
  stability: 'observed-stable' | 'changed' | 'unverified';
};
type SourceRef = {
  moduleId: string; sourceSha256: string; moduleEvidenceId: string;
  range: ByteRange; containerRange?: ByteRange;
};
type RangeEvidence = {
  sourceObservationId: string;
  coordinateSpace: 'original-file' | 'decoded-member';
  range: ByteRange; sha256: string; hashCoverage: 'complete-range';
  sourceIdentity: SourceIdentity;
  container?: {
    parentObservationId: string; parentIdentity: SourceIdentity;
    memberOccurrence: string; storage: 'stored' | 'compressed';
    encodedRanges: ByteRange[];
  };
};
type RecoveryGap = {
  code: string; phase: string; moduleId?: string; source?: SourceRef;
  affects: 'identity' | 'structure' | 'reachability' | 'value' | 'effects' | 'delivery';
};
type ClaimAuthority = 'observed-bytes' | 'static-proof' | 'candidate' | 'runtime-observation';
type ProvenValue =
  | { kind: 'number'; value: number; negativeZero: boolean } // finite only
  | { kind: 'string'; valueId: string; value?: string; codeUnits: number;
      utf16leSha256: string; availability: 'retained' | 'not-retained' }
  | { kind: 'boolean'; value: boolean }
  | { kind: 'null' };
type FeatureSelector = { modulePath: string; exportName: string };
type AnalysisViewSource =
  | { kind: 'retained'; analysisId: string; retentionId: string }
  | { kind: 'evidence-file'; path: string; sha256: string };
```

`SourceRef` is valid only for fully hashed admitted module/entry bytes. A large container can lack a whole-file hash; its selected entry digest does not become the container digest. Existing numeric byte offsets retain their old meaning; decimal-string coordinates belong to the new range schema. Do not serialize JavaScript `bigint` directly.

`moduleEvidenceId` points to the whole-module RangeEvidence; the expression range is bounded inside that module. Whole SHA is non-null if and only if SourceIdentity.hashCoverage is whole-file. Selected-ranges coverage must name the concrete range evidence. Changed/unverified identity cannot authorize handoff. Container-relative affine ranges are emitted only for stored bytes with a proven mapping; decoded compressed-member offsets never masquerade as original-file coordinates. Observation/retention nonces are provenance handles and are excluded from stable content/node commitments.

`ProvenValue` is the new graph's wire representation; old primitive-valued operation results remain compatible. Preserve negative zero and exact UTF-16 code units, including escaped lone surrogates. An omitted long string value is a labelled descriptor, not a truncated answer; exact value retrieval is bounded separately. Non-finite numbers, undefined, BigInt and Symbol remain unknown in the initial proof subset. Their JSON conversion must never manufacture null or a different primitive.

Define `ProjectAnalysis`, `ProjectFact`, `ProjectEdge`, `EffectSummary`, `StoredAnalysis`, `ReaIntegrationConfig`, `RecoveryRun`, `ArtifactSource`, `FrameworkProfile` and the research manifests in their owning plans. Each must reference the shared types above. Any contract change updates dependent tasks and tests before implementation proceeds.

F0 also defines ProducerReceipt: controller-generated id/invocationId, owned generation, tool identity, input IDs, output SHA-256, coverage, exit and cleanup state. F1's ProducerRegistry binds those records to actual owned worker/process transport and controls lookup; caller-supplied claims cannot register a receipt. Product integrations and research controllers reuse the same receipt shape without importing research scripts into product code.

### 5.3 Evidence and retained views

- Stable module/node/fact IDs hash schema tag, artifact/module digest, canonical relative location, byte range and role. Use a closed ASCII role tag and length-prefixed UTF-16LE for JavaScript string fields, preserving lone surrogate code units; raw byte digests remain byte digests. Artifact strings cannot impersonate a role tag. Analysis identity binds full admitted module inventory, entry selection, policy, tool/runtime identities and relevant upstream pin; page offset/size and session nonces are excluded.
- Parent service retains validated serialized evidence pages, never ASTs or arbitrary worker object graphs. Per-analysis sealed data cap: **4 MiB**; aggregate: **16 MiB**; at most **4** analyses; TTL **600,000 ms** measured monotonically; deterministic LRU eviction. These are initial resource targets, not existing behavior.
- New worker messages have a fixed discriminant, sequence number and per-frame serialized limit of **64 KiB**. Start/page/seal messages are validated in order; duplicate, missing, oversized or post-seal messages fail closed. Include all framing bytes in counters.
- A cancellation may retain already validated completed pages as partial evidence with interruption/gap records. It cannot invent a complete inventory or a proof whose source/identity validation never completed. Changed input invalidates proof/handoff eligibility.
- `read_analysis_view` returns an explicit missing/expired/foreign reference result. It does not reopen paths, restart an analysis or promise service retention after close. Explicit export is the only durable evidence path; validate the whole file and its schema/hash within a read budget before trusting pages.
- Each retained instance has a cryptographically random retentionId scoped to one service; content-stable analysisId alone is insufficient authority. A sealed file's digest/schema verifies integrity and shape, not its producer. Imported files are labelled unverified imported evidence and cannot authorize normalization or automatic handoff. Such actions require fresh own-analysis proofs or an independently admitted producer receipt. Read operations never silently create either.
- J4 supplies explicit `export_analysis_evidence` (workspace-backed, evidence-last) using schema `anti-bla.analysis-export/1`, bounded to the same 4 MiB sealed record cap. F2 reads that schema and pages modules/nodes/edges/facts/effects/gaps/proofs/changes plus bounded exact value bytes. Long string values use UTF-16LE byte pages with code-unit length and digest; no implicit preview becomes an exact answer.
- Public result JSON remains **64 KiB default / 256 KiB hard ceiling**; MCP escaping, caller ID and newline use the existing separate frame formula. Internal evidence retention is a separate bounded channel, not permission for a huge public response.

## 6. Resource profiles

Preserve buffered v0.1 defaults: input 64 MiB / hard ceiling 256 MiB, worker old heap 128 MiB, timeout 5,000 ms / hard ceiling 30,000 ms, one active analysis. Old heap is not a total-RSS limit.

Initial new profiles are fixed in `src/recovery/policy.ts` and `src/io/policy.ts`; changes require measured controls and explicit documentation, not automatic limit escalation:

| Limit | Initial default | Hard ceiling / rule |
| --- | --- | --- |
| Project modules | 64 | 256 |
| Project source bytes | 16 MiB cumulative | 32 MiB; each module also obeys existing JS 8 MiB admission |
| Project graph | 8,192 nodes; 32,768 edges | Refuse further expansion and retain exact gaps |
| Interprocedural context | call string length 1; 4 contexts per function | No recursive unrolling; SCC fixed-point with 8 passes, widening to unknown |
| Project work | 500,000 shared abstract steps | Exhaustion remains partial; no per-module reset loophole |
| Streaming file admission | 2 GiB | 8 GiB |
| Streaming physical reads | 512 MiB cumulative, including duplicate and hashing reads | 4 GiB; no parallel uncharged reader |
| Streaming hash work | 256 MiB | 2 GiB; also charged to physical reads |
| I/O chunks / live byte buffers | 64 KiB / 4 MiB | Live buffers hard ceiling 16 MiB |
| Read calls / retained parser index | 100,000 / 16 MiB | 200,000 / 64 MiB; account keys, previews, sets and path storage |
| Streaming metadata entries | 50,000 | 200,000; format-specific smaller limits still apply |
| ASAR streaming header | 32 MiB | 64 MiB |
| Nested structures | depth 64 | 256; cycles are graph references, not unlimited recursion |
| Decompressed/decoded output | 64 MiB cumulative | 256 MiB; charge before allocation; reject impossible expansion |
| REA attempts | 2 total | Original attempt plus one justified inspection-view attempt |
| REA integration deadline | 30,000 ms total | 120,000 ms only in explicitly configured trusted profile; includes launch, calls and delivery |
| REA remote transport | 256 KiB frame; 4 MiB retained pages total; 100 pages | Oversize terminates the owned connection with partial evidence |
| Cleanup grace / cleanup deadline | 2,000 ms before escalation / 10,000 ms separate cleanup budget | Cleanup never extends analysis eligibility; unconfirmed cleanup retains ownership and disables that profile until resolved |

Use subtraction-based bounds checks and checked integer conversion. Internally use `bigint` for file sizes/offset arithmetic, then convert to the Node API's supported position type only after proving representability. Full hashing can run out of budget/deadline: report `wholeSha256: null` and exact range/hash coverage, never a prefix digest labelled as whole-file identity. A partial hash cannot qualify a full-artifact preservation claim.

Tests enforce deterministic counters and allocation bounds. Contained qualification separately records sampled process-tree RSS, sampling coverage, kernel/container counters and wall time. Initial static streaming qualification target is **≤512 MiB observed Linux cgroup memory.peak in a 1 GiB memory-limited container**, using declared fixtures and including the analysis parent/worker cgroup. This counter includes charged memory beyond process RSS; do not label it exact RSS or compare it directly with Windows peak commit. It is a target to prove, not a product guarantee. Missing measurements remain null.

## 7. JavaScript recovery semantics

First support statically resolvable relative ESM imports/exports and conservative literal CommonJS `require`/exports. Read no `node_modules`, install scripts, arbitrary package resolution hooks, getters or target functions. Resolution mode is explicit: native node-esm requires exact file specifiers; node-cjs permits only the reviewed legacy .js/.json/.node probes, with non-JS targets kept external. TypeScript/bundler extension substitutions are not assumed. Declared policy and package type observations bind identity; ambiguous or escaping resolutions remain gaps. Preserve TypeScript/JSX loader identity. Whole-declaration import type is erased only under the declared matching policy; inline type specifiers may retain a side-effect import under verbatimModuleSyntax. The default conservative policy retains a possible runtime dependency/initialization barrier instead of claiming erasure. `eval`, `with`, mutable escaping bindings, dynamic module names, proxies and unsupported reflection prevent dependent value/effect proofs.

Extend expression proofs into parameterized function summaries and selected backward slices. Distinguish a value known on normal completion from a removable pure expression. Model constructor calls, delete, throw, writes, getters, await/yield and potentially throwing coercions before normalizing across calls. Only proven transformations enter a derivative; unreachable candidates remain candidates unless their guard/path is actually proven.

A selected fact carries entry-to-callee binding/path evidence, exact argument position, source coordinates, assumptions and gaps. A string's presence elsewhere never answers the selected call task. Cycles, dynamic dispatch and unmodeled effects widen to unknown. Do not demand whole-program success to preserve independently valid local observations; qualify the boundary explicitly.

Function summary cache keys bind the abstract arguments, immutable captures, module-initialization assumptions and bounded call string. Alternatively, a parameterized summary must be soundly instantiated/joined for every call; a context reused across f(1)/f(2) cannot reuse one constant answer. The fifth distinct context widens to unknown rather than overwriting or selecting a previous context.

## 8. REA integration lifecycle

`recover_with_rea` exists only when trusted startup configuration supplies a verified runtime/entrypoint, supported schema/pin, explicit workspace and fixed allowlist of static REA operations. Target bytes cannot supply a command, environment variable, provider or package. The controller owns one stdio MCP session and retains its parent evidence IDs for subsequent pages.

State sequence: validate input/config → verify identities → original REA summary attempt → classify actual failure/selected unanswered feature → select one supported recovery action → create/verify inspection view if justified → second REA summary/trace attempt → seal linked evidence → verify owned cleanup. A resource failure is not success; a sidecar's existence is not completion. No identical retry with unchanged input/policy.

Use REA's actual tool discovery/schema contract. Tool names in the plan are allowlist candidates, not permission to call an unadvertised operation. Preserve original raw status, coverage, limitations and source identities alongside derived conclusions. If the installed REA schema is unsupported, fail with a typed compatibility result and manual handoff instructions. Never invoke an unknown replacement tool based on a string match.

Cancellation and deadline stop new work, close the owned session, terminate/reap the owned child as necessary and retain partial result/cleanup state. Do not kill a process using a PID without a live owned handle/start identity. Do not accept another analysis as cleanly idle until lifecycle ownership is released or explicitly quarantined. Runtime-enabled REA tools are not in this profile's allowlist.

Framework integration uses a separately admitted StaticFrameworkBridge defined by R5, with fixed static Dart/IL2CPP/JNI/native calls and its own profile schema. It reuses bounded transport and ownership without broadening the JS profile's allowlist. At most 16 fixed provider calls share its configured deadline/response budgets; no generic callTool/argv/environment mutation is exposed. Optional generated Ghidra seeds require a verified seed receipt in the trusted startup recipe before provider launch; open_binary has no invented seed-file argument.

## 9. Contained research and genuine frameworks

Runtime qualification is a separate command family under `scripts/research/`; it never changes default MCP `targetExecution: false`. It admits only independently owned hash-bound fixture, runner and scenario manifests. Before execution, record and verify effective UID, mounts, no egress, read-only root, capabilities, seccomp, PID/CPU/memory budgets and image digest. Observe both configured and effective state. Missing or contradictory controls prevent launch.

Default runtime profile: network none, nonroot UID/GID 65534 where supported, all capabilities dropped, no-new-privileges, private PID namespace, read-only root, explicit read-only inputs, bounded tmpfs, 1 GiB memory, 2 CPUs, 128 PIDs. A Frida profile may need a separately reviewed minimal tracing capability/seccomp policy; it must never inherit host PID namespace or silently weaken the default. Qualification is per effective profile.

Exercise real REA collectors using independently attested producer event counts, monotonically sequenced canaries, oversized/deep event controls and concurrent sources. Record collector received/retained/dropped counts only when the actual API/instrumentation exposes them; otherwise use null/UNAVAILABLE and separate end-to-end sequence gaps from unproven stage attribution. Explicit dropped/filtered/truncated coverage is a passing loss-accounting behavior; silent loss, incorrect reconciliation or a lost result without an unknown classification fails. A helper returning a large object without emitting it does not stress a collector.

Finite behavior uses a separately admitted trusted contained runner/observer and typed RuntimeValue/RuntimeEffect schema. Passive REA captures alone cannot observe arbitrary calls, writes, constructors and throws. The runner owns its selected recording interface, reports observation limits/instrumentation effects and never receives private oracle answers. Controller-owned producer receipts bind admitted executable/input/session identities to exact output bytes; a worker-authored JSON record with matching fields is not authenticated evidence.

Flutter, Unity and JNI are separate version-bound profiles. First acquire genuine artifacts with official toolchain provenance and an independently known selected feature. Derive layout rules from matching source, validate objects/mappings and connect code bytes/bindings to the selected task through REA providers. Byte-scanned labels, filenames, snapshot magic or matching strings alone are insufficient typed/code authority. Reuse REA's IL2CPP and JNI readers/providers rather than constructing a general decompiler.

Unity tooling/license or a matching platform artifact may be unavailable. The prerequisite task records the exact absence and leaves that profile blocked; software adapters can still be unit-tested but cannot be advertised as genuine recovery. No purchases, unlicensed tool acquisition, signature bypass or arbitrary third-party execution is implicit in this plan.

## 10. Evaluation and release rules

Freeze manifests, judges, budgets and held-out fixture commitments before recovery tuning. Controller source-informed knowledge is separate from worker artifact-only access. Enforce worker/judge/other-lane separation using actual mount/OS permissions; a path convention on shared storage is insufficient.

Run three paired lanes with identical tool/runtime/budget conditions except the documented Anti-BLA addition: clean+REA, protected+REA, protected+Anti-BLA+REA. Include benign complexity, same-spelling bait, side effects, malformed structures and combined-shield controls. Test each claimed causal shield effect separately before reporting per-shield attribution.

Judge exact typed selected answers and their evidence, not stdout substring presence or a provider's `ok`. Classify correct, incorrect, unknown and invalid-trial separately; retain every scheduled trial in the published accounting and distinguish eligible-pair denominators. A candidate incremental win requires clean+REA correct, an eligible protected+REA incorrect/unknown, Anti lane correct, verified identical fixture/protocol pairing, and no hidden answer access. Eligible unknown is an actual task/analysis budget or artifact-coverage outcome under a functioning admitted provider. Missing providers, failed isolation/metering, invalid inputs/judges, unsupported host/runtime and unconfirmed cleanup are ineligible comparison records, never wins. Repeated attempts on the same artifact are not independent seeds. Tool-only and agent wins are separate predicates; the v0.2 agent-benefit gate requires the registered fresh-agent cohort.

Record all end-to-end effort, including failed calls, handoff work, startup, cleanup and judge verification. Actual model/runtime/effort and token/cost fields require observed metadata; requested values alone are not observations. Unavailable metrics are null with a reason. Report paired outcomes and censoring; do not present a speedup computed only from successful cases or a general rate from a small selected cohort.

Freeze three clocks: recovery budget ends new analysis/submission eligibility; cleanup has a separate 10,000 ms budget with 2,000 ms cooperative grace; judge verification has a 30,000 ms budget. Report recovery, cleanup, judge and total elapsed independently. Cleanup/judge time cannot extend recovery eligibility, and incomplete cleanup/judge makes the comparison ineligible.

Freeze versions, public source/claim documents and candidate commit before final package/matrix/review gates. Final gate reports/checksums may be external release assets. Any later source, version or packaged-document change invalidates the relevant candidate/package checks and returns to L0; do not put a self-referential final commit/archive digest into a committed file or silently reuse old gates.

The release plan defines per-milestone gates. Minimum publication rules: portable tests and explicit integration tests pass on supported platforms, opt-in missing-provider paths fail clearly, independent Critical/Important findings are cleared, genuine claims have three independent fixture/seed runs and independent review, packaged CLI/MCP/skill checks pass from a clean install, source privacy/license audit passes, release hashes/tag/visibility/contributor attribution are verified. New versions use new tags; `v0.1` stays immutable.

## 11. Risk decisions and unresolved research

| Risk | Required response |
| --- | --- |
| Unsound cross-module simplification | Conservative effect domain, counterexamples first, no derivative from unresolved proof |
| Decoys consume graph budgets before the real feature | Entry-directed traversal, shared counters, stable partial views; unknown when the boundary is hit |
| Parser allocations evade old-heap assumptions | Bounded input/chunks, worker isolation and measured process-tree RSS; no unmeasured memory claim |
| Source changes during a range scan | Revalidate handle/path identity and statistics; mark changed and prohibit handoff; checks are not a filesystem sandbox |
| Provider/API drift | Pin hashes/schemas, capability probe, compatibility controls and typed unsupported status |
| Benchmark overfitting or answer leakage | Sealed held-out cohorts, actual lane isolation and independent judge review |
| Genuine framework profile is not feasible | Time-bounded feasibility task with objective go/no-go artifacts; retain unsupported status and keep roadmap incomplete for that profile |
| Cleanup loses ownership or PID identity | Retain/quarantine lease, retry only through owned handles, report cleanup unknown |
| Original information was overwritten or discarded | State the information boundary; accept independent external evidence only with its own provenance |

No calendar duration or monetary estimate is asserted without observed implementation and provider availability. Execute one independently reviewable task at a time, record actual results, and revise a plan only through an explicit documented design decision.

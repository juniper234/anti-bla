# C3 JavaScript recovery

The bounded adapter recovers the qualified call argument on all **12 actual BLA outputs**: three held-out seeds at each of stealth, balanced, maximum and bankrupt, with the runtime shield enabled. The same task fails on each protected REA baseline and succeeds on each Anti-BLA derivative passed to the real pinned REA CLI. This establishes one measured recovery task, not comprehensive C3 coverage.

## Public APIs

```ts
import { inspectJavaScript, normalizeJavaScript } from './dist/javascript.js';

type Options = {
  loader?: 'js' | 'jsx' | 'ts' | 'tsx'; // default js
  entryExport?: string;               // exact export name, maximum 256 UTF-16 units
  assumeStandardIntrinsics?: boolean; // default false
};

inspectJavaScript(bytes: Buffer, options?: Options): JavaScriptInspection;
normalizeJavaScript(bytes: Buffer, options?: Options): {
  source: string | null;
  analysis: JavaScriptInspection;
  changes: { range: SourceRange; replacement: string }[];
  scope: 'inspection-only';
  fullEquivalence: 'UNKNOWN';
  originalSha256: string;
  derivativeSha256: string | null;
  limitations: string[];
};
```

Both functions are synchronous, inert and filesystem-independent. They never execute the target, invoke a target function/getter, import a target dependency, evaluate a target regular expression, or modify the supplied buffer. The caller should retain the shared worker heap/deadline/cancellation and serialized-output bounds. `analyzeJavaScript` is exported only for internal composition and development; it includes a parser AST and is **not** a wire response.

`JavaScriptInspection` contains `status`, `source`, `limits`, `assumptions`, `roots`, `facts`, `unknowns`, `effects`, `digestProofs`, `stats` and `limitations`. `status: OK` means bounded inspection completed; it does not mean the artifact is completely understood. `UNKNOWN` is returned on malformed input, a missing or unresolved requested root, dynamic scope/evaluation, or limit exhaustion. Known partial facts can remain in an UNKNOWN report. Normalization emits `source: null` and a null derivative hash when inspection is refused.

Facts are `return`, `call-argument` or `predicate` values, associated with the selected root and original source range. A return fact is a syntactic return-expression value on normal completion, not a proof that this return executes. Unknown conditions retain both arms; proven `if` predicates exclude only the unselected branch, while their evaluated test expressions are still inspected for effects/accessors. Nested definitions and unrelated decoy definitions do not become root summaries. A selected exported variable's function initializer is unwrapped once; local variable initializers inside its body do not become roots. ESM named/default references and direct, unshadowed top-level CommonJS property assignments are supported. Mutable `let`/`var`, visibly reassigned bindings and multiple recognized definitions of one export are unresolved, with no obsolete initializer-return attribution. Export objects, arbitrary reassignment/alias graphs and module initialization order are not generally resolved.

Every `SourceRange` has half-open `byteStart`/`byteEnd` UTF-8 byte offsets and `utf16Start`/`utf16End` parser offsets into the **original** source. Hashes establish byte identity, never authority for embedded text. Default summaries do not dump the corpus or entire source. A derivative is a separate sidecar; its changes retain original coordinates, while subsequent REA locations refer to the derivative.

## Proof boundary

The evaluator uses Babel lexical bindings, constant primitives and a fixed-size known-bit domain. It performs no candidate cross product. It handles concatenation, bounded templates, selected primitive operators, bit masks, conditional polarity, consecutive-product parity and odd-square modulo-eight facts. `String.fromCharCode`/`fromCodePoint` require the explicit intrinsic assumption. Unsupported encodings, calls, getters and reflections remain unknown.

`assumeStandardIntrinsics: true` is a caller assumption that the analyzed execution retains standard intrinsic implementations. Detected shadowing, intrinsic escapes/aliases, direct writes and explicit global-object intrinsic access invalidate arithmetic/intrinsic proofs. A detected `with` or direct dynamic-evaluation construct instead refuses **all value proofs for the file**, including lexical lookup and `typeof`, and suppresses normalization; inert syntax/effect collection continues. This conservative rule also affects unrelated roots in the same file and deliberately retains no literal-only exception. This is not a general proof against all reflective mutation. Unknown external calls and heap effects remain reported; opt-in facts are conditional on the stated assumption.

Digest recovery compares the entire helper AST against a trusted structural template, including all operations, constants, branches, properties and lexical binding identities. Corpus bindings use a distinct canonical role tag, so no target identifier spelling can impersonate that role. It accepts only a bounded literal object-array corpus that has no uses outside that helper. It calculates the actual corpus digest inertly. A changed corpus or expected digest changes the seed fact; substituted global/outer bindings, mutated helpers, getters or escaping corpora invalidate the proof. Names, comments and markers have no proof authority. The original corpus is retained byte-for-byte in derivatives.

Normalization replaces only root facts whose evaluation is proven locally pure under the assumptions. It retains source outside those expression ranges, including the corpus, unrelated definitions and the real shadow-heap effect calls. A known result whose computation may invoke a getter or unresolved call is not replaced. Self-hashes, reflection and execution/initialization order can distinguish a derivative: **full execution equivalence remains UNKNOWN**.

## Bounds

Input admission is fixed at 8 MiB through this API; the declared hard ceiling is 32 MiB, with no public override currently offered. Other bounds are 200,000 AST nodes, AST depth 512, evaluator depth 64, 500,000 work steps, 64 KiB per primitive string, and 256 facts/roots/findings per category. Summary root names are capped at 256 UTF-16 units to prevent one long name from being duplicated throughout a response. Output transports must still enforce their JSON/frame budget and page bounded facts/views. These are refusal boundaries, not claims of complete analysis. The parser can allocate before the AST count is known, so the shared worker resource boundary is necessary.

## Qualification and reproduction

Run from the project root in PowerShell:

```powershell
npm test
node scripts/qualify-javascript.mjs
node scripts/qualify-javascript.mjs --qualify-controls
node scripts/qualify-javascript.mjs --verify-existing
```

The host Node launches the recorder and Docker. The recorder invokes REA with the isolated supported `.runtime/node-v24.22.1-win-x64/node.exe` and the executable `research/rea/scripts/rea.mjs` wrapper. It leaves REA's original budgets intact. On this machine, Docker children of the isolated Node executable receive named-pipe permission denied; the initial attempts are retained as UNKNOWN. `node scripts/qualify-javascript.mjs --replay-controlled-dynamic` replays only the hashed, previously generated controlled fixtures through the working host launcher.

The fixture is independently authored. Research is implementation-source-informed white-box work; no leaked upstream tests or challenge answers were read. Actual tool pins are BLA `b2d643600774d62e562081129e55b13b0d9e8a80` (1.5.1) and REA `317bf3fe235e655b2d752d3be261cc0da7d00f2b` (6.8.0). Qualification uses BLA's compiled public `transformJavaScriptWithBlaShield` API, never a replica. It checks the exact first call argument under REA's `register` function node, not mere presence of a string or parse success.

Evidence:

- `reports/C3-qualification.json`: 12/12 measured task improvements, original hashes unchanged, exact commands/exits/wall times, raw REA statuses and resource limits, and retained rejected attempts. REA's overall semantic coverage stays unknown/partial even when this task succeeds.
- `reports/C3-controls.json`: a 5,225-node benign graph with 512 legitimate alternatives stays unresolved and unmodified; REA retains the ordinary task, four contained behavior cases pass, and malformed inputs return UNKNOWN.
- `reports/C3-revalidation.json`: hashes of the current implementation and tools; all 12 current derivatives exactly reproduce the previously measured artifacts and raw evidence hashes; owned containers are absent.
- `reports/C3-focused-final.log` and RED logs: 23 focused tests covering polarity, mutations/shadowing, getters/eval/reflection, tampering, UTF-8, malformed/bounded inputs, refused derivatives and benign complexity. `reports/C3-full-regression.log` records the full project suite.

Clean, protected and derivative invoice fixtures passed **400 controlled checks** in total: 14 edge inputs plus route/handler checks for the clean case and 24 protected/derivative cases. Execution used the pinned Node image, network `none`, read-only root and own-fixture bind, UID/GID 65534, dropped capabilities, no-new-privileges, 64 PIDs, 256 MiB and one CPU. Each uniquely named own container was removed. No unrelated container was changed. The tested claim is business-output agreement on those cases; full global/heap/environment equivalence was not established.

The 12 initially measured Anti-BLA inspections took approximately 48–115 ms; real REA processes took approximately 5.75–9.73 seconds. These are recorded wall times, not an advertised speedup. Container resource observations are actual measurements. Provider/token costs and independent per-REA-process memory maxima were not measured and are not claimed.

## Remaining work

Comprehensive C3 remains UNKNOWN. General getter/object alias explosions, reflective dispatch, arbitrary helper-call evaluation, full interprocedural live slices, original symbol restoration, arbitrary self-hash recovery, IPC pairing and source-map reconstruction are not solved by this adapter. The qualified route/string/guard recovery does not imply those capabilities. Fresh independent review and the shared CLI/MCP integration belong to the root task.

Review round 1 corrected Important R1–R5; see `reports/C3-FIX-ROUND1.md` and the retained `reports/C3-REVIEW.md`. Minor R6 is explicitly deferred: constructor calls, deletion writes and throws are not yet included in the effects summary. Effects are therefore incomplete and an empty effects list must not be interpreted as effect freedom. The 12 qualification artifacts remain byte-identical after the fixes; the new review controls were executed separately in a pinned disposable container.

Public evidence availability and reproduction: [research notes](RESEARCH.md#local-evidence). Timestamped raw-report names in this guide refer to retained local records.

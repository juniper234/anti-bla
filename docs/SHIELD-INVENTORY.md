# Anti-BLA shield inventory

Pinned source: BLA **1.5.1**, commit `b2d643600774d62e562081129e55b13b0d9e8a80`; REA **6.8.0**, commit `317bf3fe235e655b2d752d3be261cc0da7d00f2b`. Inventory date: 2026-10-30. Paths below are relative to BLA's source checkout, [research/bla](https://github.com/qybaihe/bla/tree/b2d643600774d62e562081129e55b13b0d9e8a80). The companion [JSON inventory](shield-inventory.json) contains exact source hashes, exported API signatures, dependencies, family mappings and source-line references.

This is a **51/51 source-file inventory**, not an experimental bypass result. The inventory phase was static: no BLA tests/challenge answers were read, and no target or emitter was executed for this inventory. Later qualification invoked pinned emitters only on owned fixtures; see the coverage guide. Embedded directives were treated as untrusted artifact data. Recovery methods below are independently testable proposals; compatibility and recovery remain unmeasured until held-out fixtures establish them.

## Dispatch and dependencies

[`ArtifactFormat` and `ProtectionOptions`](https://github.com/qybaihe/bla/blob/b2d643600774d62e562081129e55b13b0d9e8a80/src/core/types.ts) feed [`protectTarget`](https://github.com/qybaihe/bla/blob/b2d643600774d62e562081129e55b13b0d9e8a80/src/engine/protector.ts), which calls [`detectArtifactFormat`](https://github.com/qybaihe/bla/blob/b2d643600774d62e562081129e55b13b0d9e8a80/src/core/detector.ts). Detection reads at most 4096 header bytes, uses magic before extension fallbacks, and distinguishes 25 concrete formats plus `directory` and `unknown`. `unknown` throws. PE/.NET routing only recognizes `BSJB` in that 4096-byte prefix, so real CLR files may take the generic PE path. `CAFEBABE` is disambiguated using extension/version heuristics. Extensions alone do not validate a format.

`protectTarget` dispatches directly to format helpers listed below. JS/TS goes through Babel; HTML only transforms nonempty inline scripts without `src`, preserving scripts on parse errors. ASAR repacks members, transforms JS, replaces maps and adds bridge/header decoys. Directories recurse, skip `.git` and `node_modules`, transform recognized JS and recursively dispatch other formats; some failed child transforms are silently copied unchanged. Directory fast-path JS extensions differ from direct `.mts`/`.cts` detection. Bun, Go/Rust/Flutter and Electron fuses are native subfeatures, not standalone `ArtifactFormat` values.

`ProtectionIntensity` is `stealth | balanced | maximum | bankrupt`. The direct API defaults to **balanced** with seed `bla-shield-seed-v1`; [`DEFAULT_BLA_CONFIG`](https://github.com/qybaihe/bla/blob/b2d643600774d62e562081129e55b13b0d9e8a80/src/core/config.ts) defaults to **bankrupt**. Lower-level helpers have their own default seeds and some derived child seeds include file names/paths. Flags declared in `ProtectionOptions` are not all applied: the engine does not forward the tarpit/chaff/semantic/IPC/route/runtime toggles to the JS transform; its actual runtime toggle is lower-level `JsTransformOptions.enableRuntimeShield`. ASAR/directory JS branches emit honey maps independently of the direct-JS `honeySourceMaps` toggle.

Package runtime: Node `^22.13.0 || >=24.0.0`; Babel parser/traverse/generator/types `^7.26.0`; zod `^3.24.0`. SQLite transforms additionally require available `node:sqlite` `DatabaseSync`; ZIP uses `node:zlib`; hashes use `node:crypto`. Native header generation emits source for a developer's C/Rust/Go build and does not itself compile or execute it. Per-file import dependencies are preserved in the JSON. These dependencies do not authorize target execution.

| Intensity | stealth | balanced | maximum | bankrupt |
|---|---:|---:|---:|---:|
| Chaff payloads | 3 | 6 | 10 | 16 |
| JS tarpit decoy functions | 6 | 14 | 24 | 36 |
| Shadow heap slots | 16 | 32 | 48 | 64 |
| Profile alias selectors | 520 | 528 | 560 | 640 |
| Profile Cartesian branches | 24 | 28 | 32 | 36 |
| Profile obligation families | 8 | 14 | 18 | 25 |
| Callgraph SCC clusters, 5 nodes each | 2 | 4 | 6 | 8 |
| ASAR header decoy files | 4 | 8 | 64 | 4000 |
| ASAR decoy path padding characters | 24 | 48 | 256 | 4096 |
| Planned WASM interface descriptors | 12 | 24 | 48 | 128 |
| CDP JSON depth | 765 | 780 | 820 | 900 |

These are source emitter/profile values, not measured resource failures. Individual emitters use different branches. In particular, the real JS string transformation uses nine chunks regardless of the profile's `ternaryChunkCount`; some returned metrics are hard-coded or projected.

## Complete file and family map

In the table, **JS** means JS/TS, inline HTML, ASAR JS and directory JS. **Many** means shared text generation used by several listed format emitters; it is not proof of equal protection across those formats. Criteria IDs refer to the independent recovery requirements below. Each row corresponds to exactly one file. Public package-root exports are distinguished from other file exports in the JSON.

| File under `src/shields/` | Family / formats | Source-observed mechanism | Independent static opportunity | Criterion |
|---|---|---|---|---|
| `chaff/chaff-generator.ts` | chaff / Many | Seeded enclave, evidence-contract, offset-table, state-machine and crypto-manifest prose. | Demand actual code/data references before believing architectural claims. | provenance |
| `javascript/ast-shield.ts` | JS transform / JS | Babel rename/comment scrambling; nine conditional string chunks; corpus-derived seed; guards around real statements; shadow-heap and suite injection. | Binding-aware partial evaluation, exact integer congruences and effect-aware slicing. | js |
| `runtime/runtime-shield.ts` | runtime / JS | Frozen decorative shadow global, no-op event listeners, inspector heuristics, high-intensity decoy hashing. | Separate observed effects from diagnostic prose; account for globals/listeners/hash work. | js |
| `runtime/memory-diff-shield.ts` | runtime / JS | Mutable heap/diff-envelope churn, per-function stepper and two XOR shares of a decoy string. | Backward-slice business results; statically decode referenced numeric shares without running helpers. | js |
| `tarpit/opaque-predicates.ts` | tarpit / JS, Python | Generates parity, bitwise identity and quadratic guards. | Prove precise JS 32-bit/Python integer behavior before folding. | js |
| `tarpit/tarpit-generator.ts` | tarpit / JS, Python | Getter cycles, alias selectors, Cartesian string growth and dense decoy calls/docstrings. | Slice from real entry points before expanding symbolic products or SCC paths. | js |
| `exhaustion/index.ts` | exhaustion / JS | Composes obligations, labyrinth, BPE, CDP, Frida and regex generators. | Track actual calls; injected definitions are not runtime invocation. | provenance |
| `exhaustion/rea-budget-matrix.ts` | exhaustion / Many | REA constant catalog, charge estimators and intensity profiles. | Verify actual REA constants and separately identify each live emitter path. | provenance |
| `exhaustion/obligation-flooder.ts` | exhaustion / JS | Guarded IPC/bridge/routes/storage/worker/native/process/timer/managed-looking calls. | Demand reachable call sites and actual bindings before creating business obligations. | js |
| `exhaustion/callgraph-labyrinth.ts` | exhaustion / JS | Budgeted mutual-recursion SCCs and guarded dispatcher. | Prove dispatch reachability first; bound SCC indexing. | js |
| `exhaustion/bpe-token-amplifier.ts` | exhaustion / JS | High-entropy identifiers/string tables. | Keep raw tables in byte-addressed evidence; page only referenced values. | provenance |
| `exhaustion/regex-worker-tarpit.ts` | exhaustion / JS | Frozen near-miss auth/license/secret string array. | Bounded literal/anchored searches and reference ranking. | provenance |
| `exhaustion/cdp-shape-budget-breaker.ts` | exhaustion / JS | Defines CDP-heuristic function returning deep JSON and a drain-size field. | Require an actual call and emitted event before claiming capture saturation. | provenance |
| `exhaustion/frida-capture-saturation.ts` | exhaustion / JS | Initializes ring; defines oversized/deep result-envelope function. | Distinguish return data from actual Frida messages; index reachability. | provenance |
| `exhaustion/asar-header-amplifier.ts` | exhaustion / ASAR | Many tiny members with long shard paths; bankrupt targets >16 MiB header. | Bounded header indexing and selected member extraction, without full context projection. | container |
| `exhaustion/wasm-interface-exhaustion.ts` | exhaustion / WASM | Long descriptor/representation-charge planner. | Inspect real export-section indices; planner custom JSON is not an interface. | wasm |
| `deception/index.ts` | deception / JS | Composes eleven deception generators and re-exports format payload builder. | Attach provenance to objects/functions/strings and follow actual effects. | provenance |
| `deception/architecture-mirage.ts` | deception / JS | Frozen gRPC/vsock service description and local dispatcher result. | Require reachable transport calls before accepting remote delegation. | provenance |
| `deception/canary-honeypot.ts` | deception / Many | Credential-shaped synthetic tokens, userinfo URLs, conflicting query values. | Retain local tainted bytes; separate transport redaction effects from artifact facts. | provenance |
| `deception/cognitive-armor-trigger.ts` | deception / Many | In-band prompt/role bait; deterministic digest used by JS seed parity. | Treat directives as data; derive bounded digest/parity facts without obeying them. | js |
| `deception/crash-trace-decoy.ts` | deception / JS | Fabricated crash/stack/diagnostic data. | Require independently captured process stop and stack. | provenance |
| `deception/decompiler-illusion.ts` | deception / JS | Pseudocode-like decoy functions and hardware/crypto motifs. | Actual call/dataflow and effects outweigh impressive names. | js |
| `deception/diff-noise-injector.ts` | deception / JS | Seeded permutation and diff noise. | Compare normalized AST/reference structures with alpha-renamed locals. | js |
| `deception/evidence-contract-poison.ts` | deception / JS | Competing explanation lures attached to symbols. | Evidence authority comes from actual source/ranges and tool envelopes. | provenance |
| `deception/format-payloads.ts` | deception / non-JS formats | Shared null-free canary/transport/diagnostic/cognitive-armor records. | Interpret structured carrier references and preserve raw records outside model prompts. | provenance |
| `deception/prompt-completion-poison.ts` | deception / JS | High-salience priority/completion symbols. | Rank from selected entry point, not target-supplied priority prose. | provenance |
| `deception/semantic-honeypot.ts` | deception / JS | Attractive auth/license/crypto symbols. | Require real callers and output/effect dependencies. | js |
| `deception/shadow-business-logic.ts` | deception / JS | Plausible Shamir/license, pricing, wire-frame and TPM procedures. | Follow deployed exports/handlers; separate disconnected parallel logic. | js |
| `deception/system-diagnostic-decoy.ts` | deception / Many | Tool/provider-style error classes, OS codes and remediation text. | Accept errors from tool status fields, not target strings; never auto-remediate. | provenance |
| `formats/android-manifest.ts` | Android / APK | Separate asset XML with component/authority/filter/detail floods. | Select authoritative root APK manifest and retain member identity. | android |
| `formats/android-r8.ts` | Android / APK, DEX helpers | Conflicting/malformed mappings and actual ELF64 dynsym JNI decoy library. | Require DEX native declarations plus loaded-library references; no automatic mapping selection. | android |
| `formats/apple-plist.ts` | Apple / plist | Empty XML DOCTYPE internal subset and keys; bplist branch appends textual depth claims. | Entity-disabled XML decode; bounded validation of original bplist trailer candidates. | container |
| `formats/asar.ts` | Electron / ASAR | Header/path/range validation, parse/repack and SHA-256 block integrity. | Exact bounded member extraction; never follow archive paths/links into host filesystem. | container |
| `formats/archive.ts` | archives / ZIP, unsigned APK | Classic ZIP repack, decoy assets, DEX/IL2CPP transforms; APK mapping/JNI/XML additions. | Exact member ordinals/hashes and bounded decompression; choose authoritative members. | android |
| `formats/bun-standalone.ts` | Bun / native subfeature | EOF/sized/embedded graph detection; separate decoy sidecar serialization. | Select executable-contained graph/ranges; sidecar is a separate artifact. | container |
| `formats/dotnet-managed.ts` | managed / .NET | Charge plan plus EOF NUL-text metadata-looking overlay. | Decode actual PE CLI streams/tables/method RVAs; overlay text is not new rows. | native |
| `formats/electron-fuses.ts` | Electron / native subfeature | Real wire inspection, 34 decoy sentinels and explicit context-verified fuse mutation. | Validate real slice/wire/version; recognize genuine disabled inspection posture. | native |
| `formats/erlang-beam.ts` | BEAM | Preserves core chunks/indices; expands AtU8 table and adds unknown chunks. | Stream IFF chunks; preserve Code/ExpT/ImpT and referenced atom-index mapping. | beam |
| `formats/evm-bytecode.ts` | EVM | Replaces terminal CBOR; appends optional JUMPDEST padding. | Separate metadata and reachable runtime opcodes; retain code-introspection caveats. | evm |
| `formats/go-flutter-exhaustion.ts` | native metadata / Go, Flutter | Framed buildinfo, oversize claims, Dart pool/hash floods; exported ELF fixture builder. | Prefer mapped/section references; identify overwritten regions and untrusted appended candidates. | native |
| `formats/gpu-ptx.ts` | GPU / PTX only | Appends no-op .entry kernels and comments; explicit firmware/object skip reasons. | Recover original referenced kernels; account for added entry points. | gpu |
| `formats/headers.ts` | native build / C, Rust, Go | Emits source/header decoys, cross references, strings and shadow state. | Use actual compiler/linker/call references to distinguish retained unused decoys. | native |
| `formats/jvm-bytecode.ts` | JVM class | Adds Utf8 constants/cp_count then raw JSON payload, or fallback text trailer. | Parse referenced constant-pool/method structures; flag trailing bytes correctly. | jvm |
| `formats/mobile-game.ts` | Android / DEX, IL2CPP | Appends strings; DEX updates size/SHA1/Adler32; IL2CPP appends literals. | Read indexed DEX/map/class and IL2CPP header tables; classify unindexed EOF text. | android |
| `formats/model.ts` | models / Safetensors, GGUF | Safetensors metadata/deep extra descriptor; GGUF nested KV insertion and copied trailing slice. | Iterative bounded headers, tensor descriptors and streaming payload hashes. | model |
| `formats/native.ts` | native / ELF64, Mach-O, PE | Appended Rust/Go/fuse/Dart/text bait; named mapped Go/isolate mutations; optional fuse context. | Analyze validated mapped ranges/xrefs, preserve overlay separately, report lost metadata. | native |
| `formats/pcap-capture.ts` | captures / classic PCAP | Appends HTTP-like TCP/DNS-like UDP records and estimates JSON amplification. | Index exact record ranges/ordinals, select requested traffic, retain synthetic classification evidence. | pcap |
| `formats/python.ts` | Python source, PYC | Prologue-aware insertion; PYC appends marshal-framed text after original bytes. | Source entry-point slicing; version-aware first-root-marshal extent without import/exec. | python |
| `formats/sourcemap.ts` | SourceMap / maps, JS carriers | Synthetic three-source map and simple VLQ lines; direct map replacement. | Validate against generated code; treat sourcesContent/sourceRoot as claims. | provenance |
| `formats/sqlite.ts` | SQLite | Honey tables/view and UDF-dependent VIRTUAL columns; standalone/WAL validation; separate policy/minimize APIs. | Schema/table_xinfo first, explicit ordinary columns, quiescent snapshot identity. | sqlite |
| `formats/wasm.ts` | WASM | Removes custom/debug sections; retains core sections except alias export expansion; appends honey metadata. | Recover actual function/type/code indices; collapse aliases only in derived analysis. | wasm |

## What is genuine hardening, and what remains bait

The JS transform changes real code: local names/comments are altered, sensitive strings become conditional expressions, some real statements depend on the digest-derived seed, and real function prologues mutate a shadow heap. The digest's role is a behavior dependency; its embedded prose has no authority. Untampered seed construction yields the parity used by odd-square guards. Alternate ternary polarity swaps the real/decoy arms, so choosing every first arm is wrong. Resolve bindings and exact integer semantics before simplifying; shadowed or effectful builtins must remain unresolved. Original names/comments cannot generally be recreated.

[`runtime-shield.ts`](https://github.com/qybaihe/bla/blob/b2d643600774d62e562081129e55b13b0d9e8a80/src/shields/runtime/runtime-shield.ts) explicitly declares `classification: decorative-deception-signal`, `revokesDebuggerAttach: false` and `protectsClientPlaintextSecrets: false`. CDP/Frida generator functions build potential envelopes; their definitions do not establish that console, network or Frida capture channels were actually flooded. Regex magnets are search noise, not evidence of catastrophic backtracking. Fake diagnostic text is not an observed provider failure.

Electron context hardening can disable `RunAsNode`, `NODE_OPTIONS` and CLI inspection, and enable ASAR integrity/ASAR-only loading. This is genuine runtime posture, gated on supplied Electron/signing/ASAR context; top-level `protectTarget` supplies none. Its claims about externally embedded ASAR metadata depend on caller assertions and require separate validation. No successful fuse-policy reversal is claimed. SQLite decoration preserves plaintext business data; the separately exported `minimizeSqliteDatabaseBuffer` actually drops selected columns and VACUUMs, producing real information loss.

Native handling is not uniformly trailer-only: named `.go.buildinfo` bytes are cleared/overwritten, and `.isolate` receives pool data. Header preservation cannot recover those originals or establish behavior equivalence. In contrast, appended-EOF Bun executables pass through byte-exact and get a separate `.bunfs-snapshot` bait sidecar; that sidecar is not the executable's module graph. Generic trailers may invalidate code signatures/checksums, especially PE/Mach-O.

## Validity and evidence caveats that must survive reporting

- **Self-scoring:** [`auditTarget`](https://github.com/qybaihe/bla/blob/b2d643600774d62e562081129e55b13b0d9e8a80/src/engine/auditor.ts) uses AST/marker heuristics and fixed/estimated costs. [`verifyTarget`](https://github.com/qybaihe/bla/blob/b2d643600774d62e562081129e55b13b0d9e8a80/src/engine/verifier.ts) derives `functionalIntegrityVerified` solely from `sim.parseStatus === "complete"`. Neither proves execution equivalence, actual REA resource failure or a measured dollar cost. `counteredReaVectors` is intent, not independent evidence.
- **Source maps:** original maps are replaced. Generated honey maps cannot reconstruct removed provenance; derive business behavior from actual generated code.
- **WASM:** original custom/debug/name sections are dropped. Added export aliases point to function index 0; the source path requires a valid function/export context. Custom planner JSON is not a real import/export table.
- **Managed/JVM:** the .NET emitter appends text without adding CLI table/PInvoke rows. The JVM emitter appends `attrPayload` without updating `attributes_count` or framing it as an `attribute_info`; strict-reader/verifier compatibility is unproven. Counted decoy descriptors are not necessarily executable class/metadata rows.
- **Apple:** an empty XML internal subset can be evaluated without external entity expansion. A binary-plist textual depth claim is not real graph nesting. Appending after a binary plist's EOF trailer can break readers; source comments claiming compatibility are unverified. Non-plist input can become synthetic content.
- **DEX/IL2CPP/APK:** DEX added descriptors are unindexed trailer strings, not new `class_defs`; original DEX header hashes/size change. The root APK manifest and developer libraries stay intact while asset manifests/mappings and a new JNI library are added. Signed archives/APKs and unsupported classic-ZIP layouts fail closed; signing, ZIP64 and arbitrary archive support are not established. Invalid DEX/IL2CPP inputs may be replaced by synthetic headers.
- **Models:** Safetensors validates descriptor layout and preserves tensor bytes, but extra descriptor compatibility with all loaders is unproven. GGUF copies the trailing tensor-info/data slice after inserted metadata without a complete layout/alignment proof; actual tensor offsets/loader validity need independent checks. Failed GGUF parsing may produce a zero-tensor synthetic artifact. Deep metadata is not encrypted weights.
- **BEAM/EVM:** BEAM bankrupt emits 260 chunks, exceeding the cited hard ceiling 256; bounded selective parsing needs explicit omissions. EVM strips prior terminal CBOR heuristically, losing original metadata; JUMPDEST padding can change fallthrough/jumps, code size, CODECOPY and code hashes. Raw Buffer input is not automatic hex-text decoding.
- **Captures:** detection admits pcapng, but protection only accepts certain classic-PCAP magics and otherwise substitutes a new classic header, losing original input. Injected records are little-endian even on accepted big-endian bases. TCP/UDP checksums, DNS validity and tshark expansion are not independently established. PCAP output preservation must fail closed on these cases.
- **Explicit non-support:** firmware, SPIR-V, CUDA fatbinaries and AMD GPU objects have no offered shield. PTX text is the only GPU mutation surface. Native layout admission is limited by `validateElf64Layout`; do not extrapolate ELF64 guarantees to all ELF/PE/Mach-O shapes.

## Independent recovery criteria

All criteria require independently authored fixtures with held-out expected facts and unseen seeds. Upstream tests/challenge answers are excluded. Keep original/protected digests, exact source/byte ranges, parser versions, bounded-resource outcomes and unresolved counts. A successful parse is not a full-original recovery. Static proposals remain **UNMEASURED** here.

| Criterion | Minimum measurable result |
|---|---|
| provenance | Accepted claim has artifact digest/range plus a structural, call or data reference; embedded instructions remain data; no fetch, credential use or automatic remediation. |
| js | Recover expected referenced literals/routes/IPC and exported surface with binding-aware, effect-aware proof. Unknown parity/builtin semantics remain unknown. Any execution equivalence check needs a separately authorized controlled run. |
| container | All admitted header/member ranges accounted for under byte/depth/path caps; selected original member hashes match held-out originals; no link traversal or path materialization. |
| wasm | Type/function/code/data bytes and original referenced indices match; justified alias/custom changes isolated; stripped metadata explicitly unrecoverable. |
| native | Actual code/load/section references and wire candidates retained; unchanged code hashes match; mapped losses/fuse/signature changes recorded. Headers alone cannot pass equivalence. |
| android | Root manifest, indexed DEX/IL2CPP facts and actual native bindings match held-out originals; decoy asset/mapping/JNI members stay separate; checksums validated independently. |
| beam | Original Code/ExpT/ImpT and referenced atom-index mapping match; all omitted unknown chunks accounted for; classic/compact encoding distinguished. |
| evm | Exact raw/hex carrier identity, CBOR range and reachable opcode prefix match; padding/control/code-introspection dependencies explicit; stripped metadata stays unrecoverable. |
| gpu | Original PTX kernel declarations/bodies match modulo documented trailing whitespace; extra kernels accounted for; non-PTX objects/firmware unsupported. |
| jvm | Referenced original constant-pool entries and field/method/Code structures match; strict parser identifies trailing/attribute defects; no assumed verifier acceptance. |
| model | Dtype/shape/data offsets and exact tensor payload hashes match; bounded metadata accounted for; GGUF alignment and actual loader validity checked before usable-model claims. |
| pcap | Original global header, record byte hashes/ordinals and endianness match; no dropped/invented packets; pcapng substitution or malformed/mixed-endian data fails closed. |
| python | Requested source definitions or first root marshal object recovered with exact version-aware byte extent, without importing/executing; trailer strings are not code constants. |
| sqlite | Quiescent DB/WAL identity and explicit ordinary-column schema/rows/value hashes match; missing trap UDFs cannot hide unrelated business tables; source DB untouched. |

The feasible first wave is structural recovery of overlays, unindexed trailers, authoritative container members, schema-selected SQLite rows and actual tensor/core byte ranges. JS proof and native mapped-metadata loss require deeper treatment. This ordering is a research choice, not a claim that all formats have already been defeated.

## Exported API index

Signatures below are source signatures of package-root exported functions/classes. Other exported helpers, type/interface declarations, constants, re-export declarations and imports are fully indexed in the JSON. These are declarations, not execution evidence.

### src/shields/chaff/chaff-generator.ts

```ts
export function generateChaffPayloads( prng: SeededPrng, intensity: ProtectionIntensity = "balanced", ): readonly ChaffPayload[];
```

### src/shields/deception/architecture-mirage.ts

```ts
export function generateArchitectureMirage( prng: SeededPrng, intensity: ProtectionIntensity = "balanced", ): ArchitectureMirageResult;
```

### src/shields/deception/canary-honeypot.ts

```ts
export function generateCanaryHoneypot( prng: SeededPrng, intensity: ProtectionIntensity = "balanced", ): CanaryHoneypotResult;
```

### src/shields/deception/cognitive-armor-trigger.ts

```ts
export function computeContainmentCorpusDigest( entries: readonly CognitiveArmorTriggerEntry[], seedInput = 0, ): number;
export function generateCognitiveArmorTrigger( prng: SeededPrng, intensity: ProtectionIntensity = "balanced", ): CognitiveArmorTriggerResult;
```

### src/shields/deception/crash-trace-decoy.ts

```ts
export function generateCrashTraceDecoy( prng: SeededPrng, intensity: ProtectionIntensity = "balanced", ): CrashTraceDecoyResult;
```

### src/shields/deception/decompiler-illusion.ts

```ts
export function generateDecompilerPseudocodeIllusion( prng: SeededPrng, intensity: ProtectionIntensity = "balanced", ): DecompilerIllusionResult;
```

### src/shields/deception/diff-noise-injector.ts

```ts
export function generateVersionDiffNoise( prng: SeededPrng, intensity: ProtectionIntensity = "balanced", ): DiffNoiseInjectionResult;
```

### src/shields/deception/evidence-contract-poison.ts

```ts
export function generateEvidenceContractPoison( prng: SeededPrng, intensity: ProtectionIntensity = "balanced", ): EvidenceContractPoisonResult;
```

### src/shields/deception/index.ts

```ts
export function generateCounterReaDeceptionSuite( prng: SeededPrng, intensity: ProtectionIntensity = "balanced", ): CounterReaDeceptionSuiteResult;
```

### src/shields/deception/prompt-completion-poison.ts

```ts
export function generatePromptCompletionPoison( prng: SeededPrng, intensity: ProtectionIntensity = "balanced", ): PromptCompletionPoisonResult;
```

### src/shields/deception/semantic-honeypot.ts

```ts
export function generateSemanticHoneypot( prng: SeededPrng, intensity: ProtectionIntensity = "balanced", ): SemanticHoneypotResult;
```

### src/shields/deception/shadow-business-logic.ts

```ts
export function generateShadowBusinessLogic( prng: SeededPrng, intensity: ProtectionIntensity = "balanced", ): ShadowBusinessLogicResult;
```

### src/shields/deception/system-diagnostic-decoy.ts

```ts
export function generateSystemDiagnosticDecoy( prng: SeededPrng, intensity: ProtectionIntensity = "balanced", ): SystemDiagnosticDecoyResult;
```

### src/shields/exhaustion/index.ts

```ts
export function generateCounterReaExhaustionSuite( prng: SeededPrng, intensity: ProtectionIntensity = "balanced", ): CounterReaExhaustionSuiteResult;
```

### src/shields/formats/android-manifest.ts

```ts
export function generateAndroidManifestCounter( prng: SeededPrng, intensity: ProtectionIntensity = "balanced", ): AndroidManifestCounterResult;
```

### src/shields/formats/android-r8.ts

```ts
export function mangleJniIdentifier(value: string): string;
export function buildJniExportNames( prng: SeededPrng, count: number, ): string[];
export function buildJniDecoyElf64(exportNames: readonly string[]): Buffer;
export function generateAndroidR8Counter( prng: SeededPrng, intensity: ProtectionIntensity = "balanced", ): AndroidR8CounterResult;
```

### src/shields/formats/apple-plist.ts

```ts
export function protectAppleXmlPlist( rawXml: string, options: { readonly intensity?: ProtectionIntensity; readonly seed?: string | number; } = {}, ): ApplePlistShieldResult;
export function protectApplePlistBuffer( rawBuffer: Buffer, options: { readonly intensity?: ProtectionIntensity; readonly seed?: string | number; } = {}, ): { readonly buffer: Buffer; readonly triggersBudgetAbort: boolean; readonly decoyEnclaveEntitlementsAdded: number; readonly canaryTokensEmbedded: number; readonly diagnosticsEmbedded: number; readonly exceedsBinaryPlistNestingDepth: boolean; };
```

### src/shields/formats/archive.ts

```ts
export class UnsupportedArchiveError extends Error { constructor(reason: string); };
export class UnsupportedApkProtectionError extends Error { constructor(); };
export function readZipEntries(bytes: Buffer): readonly ZipEntryInfo[];
export function writeZipArchive( files: readonly { readonly name: string; readonly data: Buffer; readonly storeOnly?: boolean }[], ): Buffer;
export function protectZipOrApkBuffer( bytes: Buffer, options: { readonly intensity?: ProtectionIntensity; readonly seed?: string | number; readonly isApk?: boolean; } = {}, ): { readonly buffer: Buffer; readonly decoyEntriesInjected: number; readonly chaffPayloadsEmbedded: number; readonly canaryTokensEmbedded: number; readonly diagnosticsEmbedded: number; readonly membersHardened: number; readonly androidR8MappingBytes: number; readonly androidJniExportsPlanted: number; readonly androidManifestDecoyBytes: number; readonly androidManifestNamedComponents: number; };
```

### src/shields/formats/asar.ts

```ts
export class UnsupportedAsarError extends Error { constructor(message: string); };
export function unpackAsarBuffer( asarBytes: Buffer, options: AsarValidationOptions = {}, ): readonly VirtualAsarFile[];
export function validateAsarBuffer( bytes: Buffer, options: { readonly allowUnpacked?: boolean; readonly allowLinks?: boolean } = {}, ): readonly VirtualAsarFile[];
export function validateAsarProtectionInput( bytes: Buffer, options: { readonly allowUnpacked?: boolean; readonly allowLinks?: boolean } = {}, ): readonly VirtualAsarFile[];
export function packAsarBuffer(files: readonly VirtualAsarFile[]): Buffer;
```

### src/shields/formats/bun-standalone.ts

```ts
export function detectBunStandaloneGraph(bytes: Buffer): BunCarrierDetection;
export function serializeBunModuleGraph(input: { readonly modules: readonly BunDecoyModule[]; readonly entryPointId: number; readonly compileExecArgv: Buffer; readonly flags?: number; }): Buffer;
export function generateBunStandaloneDecoyGraph( prng: SeededPrng, intensity: ProtectionIntensity = "balanced", ): BunDecoyGraphResult;
```

### src/shields/formats/dotnet-managed.ts

```ts
export function planDotnetManagedBudgetExhaustion( prng: SeededPrng, intensity: ProtectionIntensity = "balanced", ): DotnetManagedExhaustionPlan;
export function protectDotnetManagedBuffer( rawBuffer: Buffer, options: { readonly intensity?: ProtectionIntensity; readonly seed?: string | number; } = {}, ): { readonly buffer: Buffer; readonly plan: DotnetManagedExhaustionPlan; readonly canaryTokensEmbedded: number; readonly diagnosticsEmbedded: number; };
```

### src/shields/formats/electron-fuses.ts

```ts
export class UnsupportedElectronFuseContextError extends Error { constructor(message: string); };
export function inspectElectronFusesBuffer( bytes: Buffer, ): ElectronFuseInspectionResult;
export function hardenAndOverflowElectronFuses( bytes: Buffer, prng: SeededPrng, ): { readonly patchedInPlaceCount: number; readonly decoySentinelsBuffer: Buffer; readonly decoySentinelsInjected: number; };
export function hardenElectronFusesWithContext( bytes: Buffer, context: ElectronHardeningContext, ): ElectronHardeningReport;
```

### src/shields/formats/erlang-beam.ts

```ts
export function inspectErlangBeam(bytes: Buffer): ErlangBeamInspection;
export function protectErlangBeamBuffer( input: Buffer, options: { readonly intensity?: ProtectionIntensity; readonly seed?: string; } = {}, ): { readonly buffer: Buffer; readonly chunksInjected: number; readonly atomsInjected: number; readonly canaryTokensEmbedded: number; readonly diagnosticsEmbedded: number; readonly exceedsDefaultChunkBudget: boolean; readonly exceedsDefaultAtomBudget: boolean; };
```

### src/shields/formats/evm-bytecode.ts

```ts
export function buildSolidityMetadataTrailer( entries: readonly (readonly [string, string | Buffer])[], ): Buffer;
export function inspectEvmBytecode(bytes: Buffer): EvmBytecodeInspection;
export function protectEvmBytecodeBuffer( input: Buffer, options: { readonly intensity?: ProtectionIntensity; readonly seed?: string; } = {}, ): { readonly buffer: Buffer; readonly metadataBytes: number; readonly canaryTokensEmbedded: number; readonly diagnosticsEmbedded: number; readonly paddingBytes: number; readonly approachesInputBudget: boolean; };
```

### src/shields/formats/go-flutter-exhaustion.ts

```ts
export function buildGoBuildInfoExhaustionPayload( prng: SeededPrng, intensity: ProtectionIntensity = "balanced", ): { readonly buffer: Buffer; readonly exceedsMaxBuildInfoBytes: boolean; readonly moduleBytes: number; };
export function buildMappedGoBuildInfoPlant( intensity: ProtectionIntensity, capacity: number, ): { readonly buffer: Buffer; readonly tripsMaxBuildInfoBytes: boolean; };
export function buildMappedFlutterIsolatePoolPlant( capacity: number, prng: SeededPrng, options: { readonly includeSnapshotHeader?: boolean } = {}, ): { readonly buffer: Buffer; readonly packageAndDartUris: number; readonly classLikeTokens: number; readonly snapshotHeaderBytes: number; };
export function buildFlutterPoolExhaustionPayload(prng: SeededPrng): { readonly buffer: Buffer; readonly snapshotHashes: number; readonly packageAndDartUris: number; readonly classLikeTokens: number; };
export function buildMappedGoFlutterElfFixture(): Buffer;
```

### src/shields/formats/gpu-ptx.ts

```ts
export function inspectGpuPtx(text: string): GpuPtxInspection;
export function protectGpuPtxText( input: string, options: { readonly intensity?: ProtectionIntensity; readonly seed?: string; } = {}, ): { readonly text: string; readonly entriesInjected: number; readonly canaryTokensEmbedded: number; readonly diagnosticsEmbedded: number; };
```

### src/shields/formats/headers.ts

```ts
export function emitCompileTimeNativeHeader( language: NativeHeaderLanguage, options: { readonly intensity?: ProtectionIntensity; readonly seed?: string | number; } = {}, ): EmittedNativeHeader;
```

### src/shields/formats/jvm-bytecode.ts

```ts
export function protectJvmClassBuffer( rawBuffer: Buffer, options: { readonly intensity: ProtectionIntensity; readonly seed: string | number; }, ): JvmClassProtectionResult;
```

### src/shields/formats/mobile-game.ts

```ts
export function inspectAndroidDex(bytes: Buffer): { readonly validDex: boolean; readonly version: string; readonly fileSize: number; readonly blaProtected: boolean; };
export function protectAndroidDexBuffer( bytes: Buffer, options: { readonly intensity?: ProtectionIntensity; readonly seed?: string | number; } = {}, ): { readonly buffer: Buffer; readonly decoyClassesInjected: number; readonly chaffPayloadsEmbedded: number; readonly canaryTokensEmbedded: number; readonly diagnosticsEmbedded: number; };
export function protectIl2cppMetadataBuffer( bytes: Buffer, options: { readonly intensity?: ProtectionIntensity; readonly seed?: string | number; } = {}, ): { readonly buffer: Buffer; readonly decoyLiteralsInjected: number; readonly chaffPayloadsEmbedded: number; readonly canaryTokensEmbedded: number; readonly diagnosticsEmbedded: number; };
```

### src/shields/formats/model.ts

```ts
export class InvalidSafetensorsError extends Error { constructor(reason: string); };
export function validateSafetensorsBuffer(bytes: Buffer): { header: Record<string, unknown>; tensorData: Buffer; };
export function buildSafetensorsBuffer( headerObj: Record<string, unknown>, tensorData: Buffer = Buffer.alloc(16, 0), ): Buffer;
export function inspectModelBuffer(bytes: Buffer): ModelInspectionSummary;
export function protectSafetensorsBuffer( bytes: Buffer, options: { readonly intensity?: ProtectionIntensity; readonly seed?: string | number; } = {}, ): { readonly buffer: Buffer; readonly chaffPayloadsEmbedded: number; readonly triggeredJsonNestingBreaker: boolean; readonly canaryTokensEmbedded: number; readonly diagnosticsEmbedded: number; };
export function protectGgufBuffer( bytes: Buffer, options: { readonly intensity?: ProtectionIntensity; readonly seed?: string | number; } = {}, ): { readonly buffer: Buffer; readonly chaffPayloadsEmbedded: number; readonly triggeredMetadataNestingBreaker: boolean; readonly canaryTokensEmbedded: number; readonly diagnosticsEmbedded: number; };
```

### src/shields/formats/native.ts

```ts
export class InvalidNativeBinaryError extends Error { constructor(message: string); };
export function validateElf64Layout(bytes: Buffer): Elf64LayoutSummary;
export function inspectNativeBinary(bytes: Buffer): NativeBinaryInspection;
export function buildDecoyRustAuditablePayload(prng: SeededPrng): Buffer;
export function protectNativeBinary( bytes: Buffer, options: { readonly intensity?: ProtectionIntensity; readonly seed?: string | number; readonly electronHardeningContext?: ElectronHardeningContext; } = {}, ): { readonly buffer: Buffer; readonly rustcHashesInjected: number; readonly electronFuseSentinelsInjected: number; readonly dartSnapshotHashesInjected: number; readonly dartPoolUrisInjected: number; readonly dartPoolTokensInjected: number; readonly goBuildInfoExceedsLimit: boolean; readonly mappedGoBuildInfoPlanted: boolean; readonly mappedFlutterPoolPlanted: boolean; readonly chaffPayloadsEmbedded: number; readonly binarySectionsPatched: number; readonly electronHardeningReport?: ElectronHardeningReport; readonly bunStandaloneCarrier: BunCarrierDetection["kind"]; readonly bunStandaloneGraphPreserved: boolean; };
```

### src/shields/formats/pcap-capture.ts

```ts
export function inspectPcapCapture(bytes: Buffer): PcapInspection;
export function protectPcapCaptureBuffer( input: Buffer, options: { readonly intensity?: ProtectionIntensity; readonly seed?: string; } = {}, ): { readonly buffer: Buffer; readonly packetsInjected: number; readonly canaryTokensEmbedded: number; readonly diagnosticsEmbedded: number; readonly estimatedTsharkJsonBytes: number; readonly exceedsTsharkJsonBudget: boolean; };
```

### src/shields/formats/python.ts

```ts
export class InvalidPythonSourceError extends Error { constructor(message: string); };
export function findPythonPrologueInsertionOffset( source: string, ): PythonPrologueAnalysis;
export function protectPythonSource( source: string, options: { readonly intensity?: ProtectionIntensity; readonly seed?: string | number; } = {}, ): { readonly code: string; readonly decoyFunctionsInjected: number; readonly crossReferenceEdges: number; readonly chaffPayloadsEmbedded: number; readonly canaryTokensEmbedded: number; readonly diagnosticsEmbedded: number; };
export function inspectPythonPyc(bytes: Buffer): PythonPycInspectionSummary;
export function protectPythonPycBuffer( bytes: Buffer, options: { readonly intensity?: ProtectionIntensity; readonly seed?: string | number; } = {}, ): { readonly buffer: Buffer; readonly chaffPayloadsEmbedded: number; readonly canaryTokensEmbedded: number; readonly diagnosticsEmbedded: number; };
```

### src/shields/formats/sourcemap.ts

```ts
export function generateHoneySourceMap( targetFilename: string, lineCount: number, prng: SeededPrng, chaffPayloads: readonly ChaffPayload[], ): { readonly mapObject: HoneySourceMap; readonly jsonString: string; readonly inlineDirective: string; };
```

### src/shields/formats/sqlite.ts

```ts
export class SqliteWalConsistencyError extends Error { constructor(reason: string); };
export function validateSqliteFileInput(dbPath: string): Buffer;
export function validateSqliteStandaloneBuffer(bytes: Buffer): void;
export function evaluateSqliteSensitivityPolicy( bytes: Buffer, policy: SqliteSensitivityPolicy = DEFAULT_SQLITE_SENSITIVITY_POLICY, ): SqlitePolicyEvaluationReport;
export function inspectSqliteBuffer( bytes: Buffer, policy: SqliteSensitivityPolicy = DEFAULT_SQLITE_SENSITIVITY_POLICY, ): SqliteInspectionSummary;
export function minimizeSqliteDatabaseBuffer( bytes: Buffer, columnsToDrop: readonly { readonly table: string; readonly column: string }[], ): Buffer;
export function protectSqliteBuffer( bytes: Buffer, options: { readonly intensity?: ProtectionIntensity; readonly seed?: string | number; } = {}, ): { readonly buffer: Buffer; readonly honeyTablesInjected: number; readonly generatedTrapColumnsAdded: number; readonly chaffPayloadsEmbedded: number; readonly canaryTokensEmbedded: number; readonly diagnosticsEmbedded: number; readonly decorationState: "decorated"; readonly businessDataState: "business-data-preserved" | "empty"; readonly confidentialityState: "confidentiality-not-established" | "policy-violation-exposed"; };
export function buildSampleSqliteDatabase(): Buffer;
```

### src/shields/formats/wasm.ts

```ts
export function inspectWasmBinary(bytes: Buffer): WasmInspectionSummary;
export function protectWasmBinary( bytes: Buffer, options: { readonly intensity?: ProtectionIntensity; readonly seed?: string | number; } = {}, ): { readonly buffer: Buffer; readonly customSectionsAdded: number; readonly chaffPayloadsEmbedded: number; readonly canaryTokensEmbedded: number; readonly diagnosticsEmbedded: number; readonly interfaceDescriptorsEmbedded: number; readonly projectedInterfaceChargeBytes: number; readonly exceedsRepresentationBudget: boolean; readonly exportDecoysInjected: number; };
```

### src/shields/javascript/ast-shield.ts

```ts
export class InvalidJavaScriptCarrierError extends Error { constructor(message: string); };
export function inferJsLoaderFromPath(filename?: string): JsLoaderType;
export function inferJsCarrierFromPath(filename?: string): JsCarrierType;
export function collectEsmExportedSymbols(program: t.Program): string[];
export function transformJavaScriptWithBlaShield( source: string, options: JsTransformOptions = {}, ): JsShieldTransformResult;
```

### src/shields/runtime/memory-diff-shield.ts

```ts
export function generateShadowHeapChurnShield( prng: SeededPrng, intensity: ProtectionIntensity = "balanced", ): ShadowHeapChurnShieldResult;
export function encodeSplitShareString( value: string, prng: SeededPrng, ): SplitShareEncodedString;
export function generateSplitShareRuntimeHelper( tag: string, stepperFunctionName?: string, ): { readonly helperFunctionName: string; readonly code: string; };
```

### src/shields/runtime/runtime-shield.ts

```ts
export function generateRuntimeDeceptionSnippet( prng: SeededPrng, intensity: ProtectionIntensity, chaffPayloads: readonly ChaffPayload[], ): { readonly code: string; readonly shadowListenersCount: number; readonly shadowGlobalsCount: number; readonly classification: "decorative-deception-signal"; readonly revokesDebuggerAttach: false; readonly protectsClientPlaintextSecrets: false; };
```

### src/shields/tarpit/tarpit-generator.ts

```ts
export function generateJsTarpitAndBudgetBreaker( prng: SeededPrng, intensity: ProtectionIntensity, chaffPayloads: readonly ChaffPayload[], ): TarpitGenerationResult;
export function generatePythonTarpit( prng: SeededPrng, intensity: ProtectionIntensity, chaffPayloads: readonly ChaffPayload[], ): TarpitGenerationResult;
```

Public evidence availability and reproduction: [research notes](RESEARCH.md#local-evidence). Timestamped raw-report names in this guide refer to retained local records.

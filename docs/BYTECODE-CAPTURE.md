# C6 bytecode, recorded capture and runtime qualification

The measured outcome is a focused OTP handoff for BEAM, successful existing REA workflows for EVM/PCAP/PTX/DEX/R8, and actual contained CDP and Frida observations for the selected JavaScript task. No duplicate product bytecode parser was added. Genuine Unity IL2CPP app recovery, GPU execution and REA capture-collector saturation remain **UNKNOWN**. These are implementation-worker observations pending fresh independent review, not a comprehensive C6 PASS.

## Evidence and identities

All targets are independently authored fixtures. BLA tests/challenges and their leaked answers were excluded. The work is source-informed, not a blind artifact-only trial.

* BLA `b2d643600774d62e562081129e55b13b0d9e8a80`, package 1.5.1, actual public emitters/`protectTarget`.
* REA `317bf3fe235e655b2d752d3be261cc0da7d00f2b`, package 6.8.0, real launcher `research/rea/scripts/rea.mjs`; local calls use isolated Node 24.22.1. Linux calls use the source checkout's launcher and dist in the pinned image.
* Genuine `javac --release 8` under JDK 24; genuine D8 and R8 **9.1.31**, build `60751e845e0a27ed4dd4f3d50e53c9f196fa30bb`, supplied by the checksum-recorded local JADX headless JAR. This compiler identity differs from BLA's fake mapping/compiler declarations.
* OTP 25 `erlc`, `beam_lib` and `beam_disasm`; Debian `erlang-base`/`erlang-dev` `1:25.2.3+dfsg-1+deb12u4`.
* TShark/capinfos **4.0.17**, Debian `4.0.17-0+deb12u3`.
* Genuine Frida **17.4.2**, Linux wheel `frida-17.4.2-cp37-abi3-manylinux_2_5_x86_64.whl`, SHA-256 `ecb1b23571ae56711e22119ebcb1e9f6fad5227a97f13706bbfc12d864602085`, verified against the retained official PyPI release-index digest before extraction. Frida is loaded only inside the owned isolated container.
* Owned tool image `sha256:66e23b9aef97a5f63033c28cf3ed1302baa55efa3287d809173d23160a445feb`, built from existing official Node image `node@sha256:d862bb5d082c5ae0210ac07e8c0344cb8cf7bef6d78e9b8c50c179da923108ea` and Debian signature-verified apt packages. [Build log](../reports/README.md) retains package acquisition/version evidence. The tracked helper contains the exact Dockerfile. OTP and Wireshark remain analysis tools, not redistributed product dependencies.

Each run retains source/compiled input/protected/derived bytes, SHA-256, own seed, actual command/arguments/exit/wall time, tool output hashes, controls and selected assertions. Peak RSS, CPU seconds, tokens and cost were not measured; those fields remain null. Emitter projections are not observed damage scores.

| Record | What it establishes |
|---|---|
| [Static qualification](../reports/README.md) | Three own seeds each for genuine BEAM, independent EVM bytecode, recorded PCAP, authored PTX and explicitly synthetic IL2CPP metadata |
| [Mobile and rejected CDP attempt](../reports/README.md) | Three genuine D8/R8 runs; its three failed dynamic-import CDP records are rejected |
| [Corrected actual CDP](../reports/README.md) | Three exact clean/protected/Anti-derived endpoint/amount observations and V8 precise function coverage |
| [Genuine obfuscated R8 and sidecars](../reports/README.md) | Three genuine R8-renamed DEX artifacts, exact public BLA mapping/XML/JNI sidecars, root-member attribution and raw method recovery |
| [Complex controls](../reports/README.md) | Repeated BEAM/PCAP/PTX tasks against 260 ordinary IFF chunks, 161 ordinary packets and 129 ordinary PTX entries respectively |
| [Actual Frida](../reports/README.md) | Three seeds × clean/protected/Anti-derived: all nine actual child attaches, agent loads, intercepted libc writes and exact endpoint/amount observations succeed |
| [Integrity and actual invocation audit](../reports/README.md) | 923 retained identities rehashed, zero mismatches; three accepted and three rejected CDP records; no owned containers remain |

## Per-family selected task matrix

Counts below mean three distinct fixture seeds, with constants `(3,11)`, `(5,13)`, `(7,17)`. They do not count retries as independent seeds.

| Family and selected task | Clean | Actual protected | Anti-assisted/tool handoff | Interpretation |
|---|---|---|---|---|
| Genuine BEAM: exported `score/1`, multiply/add constants | REA + OTP recover | REA refuses 260 chunks, including raised hard maximum 256; OTP recovers 3/3 | Immutable bounded byte provenance + focused OTP read recovers 3/3 | Useful official-tool countermeasure; capacity refusal itself is not recovery |
| EVM: dispatcher selectors `11223344`, `55667788`, `99aabbcc` | EVMole/REA 3/3 | EVMole/REA 3/3 at 4,190,208 protected bytes | Original unchanged carrier + bounded provenance + same source REA 3/3 | Baseline already works; no incremental Anti bypass |
| PCAP: original frame's UDP endpoints, port 42123 and exact payload | Selected fields 3/3 | Selected fields and legacy summary both succeed 3/3 | Original unchanged capture + exact field/filter selection and byte provenance 3/3 | Baseline already works; emitted amplification estimate did not establish a failure |
| PTX: selected entry, parameter count and instruction bytes | REA static declarations 3/3 | REA static declarations 3/3 among 128 added entries | Exact bounded selected byte view and REA handoff 3/3 | Baseline already works; no assembler/GPU equivalence claim |
| Genuine D8 DEX: `OwnedFixture.score(int)` body | JADX/REA 3/3 | JADX/REA 3/3 | Same raw method selection + indexed table byte provenance 3/3 | Baseline already works; unindexed descriptor strings are not class definitions |
| Genuine obfuscated R8: raw `a.a.a.a(int)` body | JADX/REA 3/3 | Raw method 3/3 with BLA trailer and generated sidecars | Raw selection 3/3; genuine external mapping and conflicting BLA mapping measured separately | Selected body recoverable. Original names require trusted mapping; counterfeit names are not authenticated |
| APK root manifest/JNI: authoritative package, native declaration association | Own code-only APK | Generated BLA mapping/XML/JNI members added | Root package, selected body, native declaration and no false JNI binding 3/3 | Static baseline already scopes authoritative members/declarations; library loading and execution UNKNOWN |
| IL2CPP synthetic metadata: one referenced literal | Parser control 3/3 | Parser control 3/3 | Bounded source bytes and same parser 3/3 | **Parser control only. Genuine Unity artifact/native pair absent; app recovery UNKNOWN** |
| Runtime: exact exported route call, real CDP attachment | 3/3 | 3/3 | Anti inspection derivative 3/3 | Actual selected runtime task; no independent Frida/REA event-collector saturation claim |
| Runtime: actual Frida child attachment and intercepted route-output write | 3/3 | 3/3 | Anti inspection derivative 3/3 | Real Frida agent/Interceptor path; no REA collector saturation claim |

## What the observations mean

BEAM inputs are genuine `erlc` output, not magic-bearing stubs. BLA changes the atom table and appends unknown IFF chunks while retaining core code/export/import data. REA reports `resource_constraint`, with the exact message `BEAM form exceeds the 256-chunk budget.` at its maximum allowed setting. Increasing that setting further is unavailable. OTP's static readers recover the selected export and instruction constants without loading or invoking the module. The complex benign IFF control also has 260 chunks; names are not used as a deletion rule. Originals remain intact. No inspection-only derivative is represented as a valid replacement executable.

EVM fixtures are independently authored legacy assembly, **not solc output**. The dispatcher has a JUMPDEST at byte 20 and terminating RETURN/REVERT paths. BLA's terminal `solc` declaration is untrusted metadata. Source REA's supported Linux profile inferred all selected selectors from the full protected carrier; Windows source REA correctly reports the unsupported host. Selector inference does not establish source ABI, deployed authenticity, hardfork, code-introspection equivalence or runtime/init-code identity. No RPC, chain, transaction or EVM execution occurred.

PCAP files contain only authored Ethernet/IPv4/UDP frames with documentation addresses and valid IPv4 checksums. Actual BLA appends 160 records to each original packet. TShark and source REA recover the selected original payload from the unchanged capture, using explicit fields and a port filter. The original packet prefix is byte-identical. Both legacy summary and selected-field baselines succeed; BLA's estimated JSON expansion is not an observed overflow. The stronger benign capture contains 161 independently constructed ordinary packets. Nothing acquired live traffic, installed a capture driver, opened a network interface or fetched recorded addresses.

PTX files are authored assembly with a selected arithmetic kernel. REA inspects static declarations, and Anti's existing `read-artifact-view` preserves the selected instruction bytes exactly with source offset/hash. The caller-selected extent is informed by the owned fixture, not automatic general kernel discovery. A deliberately malformed entry returns exit 0 with an empty kernel list and **partial payload coverage**. That is retained as a parser limitation, not claimed malformed refusal or assembler validity. No `ptxas`/nvcc toolchain or disposable GPU execution was qualified. A host NVIDIA driver/device exists, which does not establish target compilation or runtime equivalence.

DEX artifacts are real javac→D8 compiler output. BLA updates file size, SHA-1 signature and Adler32 and adds text after the original DEX structures. The report records original/protected `class_defs_size`, exact class-table byte range and equal table hashes. Appended descriptor strings do not become new `class_def_item` rows. JADX still reconstructs the exact selected arithmetic. APK wrappers are unsigned code-only ZIPs with text manifests; installability, binary AXML/resources, signing and Android runtime behavior remain UNKNOWN.

The stronger R8 fixture actually renames `OwnedFixture` to `a.a.a` and `score` to `a` with genuine R8. That residual intentionally collides with unmodified BLA-generated mappings. REA can still recover the exact raw body when given no mapping, the genuine compiler mapping, or the conflicting BLA mapping; raw method identity is preserved separately from mapping candidates. The counterfeit mapping returns ambiguous class/method attribution with 64 candidate records, not authenticated original names. This is not recovery of genuine source names from a fake mapping. Exact generated asset XML is not substituted for root `AndroidManifest.xml`. BLA's injected JNI ELF symbols are undefined, name-only entries; they do not implement native methods. Source REA retains the own real DEX native declaration and does not create a false binding to these names. Real dynamic registration/loading and native implementation recovery remain UNKNOWN.

IL2CPP fixtures explicitly construct bounded version 29 metadata tables and one referenced literal. They establish parser behavior against appended unreferenced text. They have no Unity build provenance, linked native implementation or actual game. The next step requires an independently owned Unity IL2CPP build or an authorized genuine `global-metadata.dat` plus matching `GameAssembly`/`libil2cpp` pair. No real-app victory is credited to these synthetic controls.

## Cross-cutting shield attribution

The corrected runtime probe connects over an actual loopback CDP WebSocket **inside** each disposable network-none container, starts V8 precise coverage, imports the actual generated module and invokes the declared own export once. The target's exact endpoint and amount agree for clean, protected and Anti-derived code across all three seeds. The decorative shadow reports `inspectorObserved: true`; it does not prevent attachment. The probe deliberately reads the decorative getter after the business call, so getter invocation is observation-induced.

The public emitter records the requested `runtimeDeception: true`, but its engine does not forward that toggle to the JavaScript transformer. Runtime inclusion follows the transformer's default and is independently confirmed by actual initializer coverage. These observations do not imply that the public toggle is honored.

| Shield | Measured / source boundary | Claim retained |
|---|---|---|
| Shadow heap churn | Actual generated stepper invoked once per selected business call | Real runtime mutation exists; global memory-diff/watchpoint defeat is unmeasured |
| Decorative runtime initializer | Actual initializer invoked once; inspector presence observed | Decoration is not OS/debugger enforcement |
| CDP shape breaker | `cdpShapeBudgetGuard_*` has zero V8 invocations on this task; source returns an envelope | No observed shape flood or REA capture loss |
| Frida saturator | `fridaCaptureSaturator_*` zero V8 invocations on the selected CDP task; ring initialization is distinct from saturation; separate actual Frida child attach/interception succeeds | Actual Frida path measured; REA Frida collector saturation remains UNKNOWN |
| Obligation flood | `obligationFlood_*` zero invocations | Source-defined static recognizer bait; independent ledger inflation/damage UNKNOWN |
| Version diff noise | Eight `diffFrontier_*` definitions per bankrupt artifact, zero invocations | No independent paired-version semantic/damage qualification |
| Crash trace decoy | `crashSignalHandler_*` zero invocations | Stored strings are not crash observations; no independent crash-localization result |
| System diagnostic decoys | `collectEnvironmentDiagnostics_*` zero invocations | Embedded remediation prose has no tool/host authority |
| Evidence-contract lures | Generated metadata/constant construction and source provenance | They do not authenticate architectural claims; no model-inference/cost experiment was run |
| Genuine Electron hardening | Separate C5 native/fuse evidence | Actual fuses remain distinct from runtime shadow flags; no live Electron attach bypass here |

V8 ranges are UTF-16 offsets in the exact protected source. The integrity/attribution audit maps these ranges to original UTF-8 byte offsets/hashes. A zero count is bounded to the one declared module initialization/export call; it does not establish absence for all inputs or direct calls to helper functions. We never force-call a saturator and relabel its returned object a live capture.

The separate genuine Frida probe spawns only a trusted launcher for the same owned fixture modules, attaches a real Frida agent before resuming, intercepts bounded stdout writes through libc `write`, and receives both Frida agent messages and actual child output. All nine clean/protected/Anti-derived cases recover the exact route and amount. The Gum agent realm is distinct from the target JavaScript global. This is an actual instrumentation path, not a projected envelope or replica; it does not run REA's Frida collector and therefore does not measure that collector's depth, truncation or loss policies. The same network-none/read-only/UID/cap-drop profile was retained; no ptrace capability, seccomp exception, ACL or driver was added. Frida native code was never imported on the host.

Earlier [C3 evidence](../reports/README.md) establishes three seeds × four actual intensities for the selected JavaScript static recovery task, with runtime shielding included. It does not separately attribute each shield's effectiveness. C4 covers actual ASAR admission/member extraction; C5 covers native layouts/fuses/metadata and its own limitations. The C6 container batch supplies managed/JVM/Python/archive/HTML carrier evidence. This batch adds actual invocation coverage and bytecode/capture observations without retroactively promoting those records to broad PASS.

The first CDP attempt connected but failed all selected tasks with `ERR_VM_DYNAMIC_IMPORT_CALLBACK_MISSING`: Node's `Runtime.evaluate` lacks an import callback. Its three records are retained and rejected. The corrected probe defines a trusted loader in the real ESM launcher, then invokes it over CDP. No protected artifact was changed to repair this harness failure.

## Reproduce and review

From the project directory, use the sanctioned ordinary PowerShell/host Node Docker context. Isolated Node children previously encountered named-pipe denial; no ACL/security changes are made.

```powershell
. '.runtime/providers/environment.ps1'
docker build --progress plain -t anti-bla-bytecode-tools:20261030 'scratch/bytecode/tool-image'
node scripts/qualify-bytecode.mjs
node scripts/qualify-bytecode.mjs --families=complex-controls
node test/helpers/bytecode-frida.mjs
```

The tracked fixture helper contains the Dockerfile if the scratch build context is absent. The orchestrator records the actual image identity on every run; rebuilding later may select newer Debian package versions and is a new qualification, not a replay of the old image identity. For the recorded image, select its immutable ID. All container invocations are named/owned, `--network none`, read-only root and fixture/REA binds, UID 65534, cap-drop ALL, no-new-privileges, PID limit 128, memory 1536 MiB, CPU limit 2, and a bounded temporary filesystem. Trusted compilation/static tools execute; arbitrary target code never executes on the host.

`test/helpers/bytecode-audit.mjs` accepts explicit report paths and rehashes retained identities, records upstream source/tool identities, maps actual CDP coverage and checks no owned containers remain. Its authority is still implementation-worker; fresh review is required. No product source/contracts/CLI/service/package files or other workers' modules were changed. No detector, traffic probe, target-derived command/URL, global configuration, driver or security change was added.

Public evidence availability and reproduction: [research notes](RESEARCH.md#local-evidence). Timestamped raw-report names in this guide refer to retained local records.

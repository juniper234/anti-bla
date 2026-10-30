# Development roadmap

Anti-BLA's next objective is to help REA answer application questions that remain unresolved on a protected artifact, with enough evidence to verify the answer. More recognized formats or more matching strings are useful only when they support that objective.

**Status: planned, not implemented or qualified.** The current release remains [v0.1](https://github.com/juniper234/anti-bla/releases/tag/v0.1). This roadmap does not change its measured results.

| Milestone | Deliverable | Evidence required before release |
| --- | --- | --- |
| Foundation | Shared evidence, retained views, resource accounting and independent evaluation contracts | Compatibility controls, cancellation, bounds and isolation tests |
| v0.2 | Cross-module JavaScript feature recovery and automatic handoff to REA | Held-out paired tasks demonstrating a new recovery benefit, with benign controls |
| v0.3 | Streaming ASAR, native/Bun and selected data-format inspection | Exact selected bytes, bounded memory, malformed controls and genuine large artifacts |
| v0.4 | Contained behavioral verification and capture stress testing | Verified containment, actual REA collector tests, explicit loss and cleanup records |
| v0.5 | Qualified Flutter, Unity IL2CPP and Android JNI recovery profiles | Matching genuine builds, code/binding evidence, independent review and explicit unsupported profiles |

Version numbers are proposed release boundaries, not promises that unqualified research will succeed. A failed prerequisite blocks that profile; it never becomes a synthetic substitute or a completed milestone.

The [engineering design](superpowers/specs/2026-10-30-comprehensive-recovery-design.md) defines the scope and shared contracts. The [master implementation plan](superpowers/plans/2026-10-30-comprehensive-recovery.md) gives the dependency order, task ownership, release gates and execution checklist. Its linked workstream plans specify files, interfaces, tests and commit boundaries.

The first implementation sequence is **foundation → sealed benchmark baseline → JavaScript recovery → REA orchestration → held-out evaluation → v0.2**. Streaming work can proceed after the shared contracts are fixed; runtime and framework work depend on genuine provider/fixture admission.

For what already works, read [measured coverage](COVERAGE.md). In particular, v0.1's fresh-agent trial established **no incremental agent recovery win**. Future reports must preserve that result and publish unsuccessful outcomes alongside successful ones.

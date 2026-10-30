# Release and Compatibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish only reviewed, reproducible milestones whose source, package, evidence, support claims and GitHub state agree.

**Architecture:** Apply the same package/matrix/review/evidence/publication sequence at every proposed release. Keep portable tests independent of optional tools and historical private evidence; require genuine integration separately for each claim.

**Tech Stack:** Existing npm lock/shrinkwrap, TypeScript, node:test, package-smoke/release auditor, GitHub Actions and authenticated Git/GitHub CLI using the operator's existing secure credential store.

**Spec:** [Engineering design](../../specs/2026-10-30-comprehensive-recovery-design.md), sections 4 and 10; [master milestones](../2026-10-30-comprehensive-recovery.md#release-slices-and-objective-exit-gates).

## Global Constraints

- Keep Node.js `>=24.16.0` for the existing product. Initial REA integration uses a separately admitted Node.js `24.22.1` runtime.
- Existing `anti-bla.result/1`, `status: ok|unknown|error`, CLI exits 0/3/2, and `behavioralEquivalence: unknown` remain compatible.
- Missing prerequisites and excluded research tests never count as passes.
- No AI/co-author attribution in commits or release text. Raw traces, credentials, local paths and downloads stay out of Git.
- New versions use new tags; `v0.1` stays immutable. No npm publication or global client registration is implicit.

## Review Focus

1. Package whitelist omits a new runtime module/notice or bundles raw evidence/tools: clean-install audit fails (L0).
2. Mocks pass while real REA schema/platform is unsupported: genuine integration cell remains unavailable (L1).
3. Support summary promotes a parser/candidate/partial task to semantic or runtime recovery: evidence gate rejects (L2).
4. Version/tag/package digest/README evidence refer to different commits: publication stops (L3).
5. Author/co-author attribution or GitHub contributor cache differs from intended owner-only history: inspect both commits and remote indexes (L3).

## Task L0: Clean package and source privacy/license audit

**Files:** Modify `scripts/package-smoke.mjs`, `scripts/check-release.mjs`, package manifest/lock/shrinkwrap, runtime/plugin versions and public release documents as required; create `test/release-capabilities.test.mjs`; update `THIRD_PARTY_NOTICES.md` only for actual new dependencies/source reuse.

**Consumes:** F3 plus the candidate's completed workstream. **Produces:** A fresh candidate tarball, clean isolated-install evidence and an exact reviewed public-source/package inventory.

- [ ] Select the next unused milestone version and update package/lock/shrinkwrap, src/contracts.ts, both plugin manifests and versioned public documents together. Prepare truthful summaries from completed qualification, commit/freeze the exact candidate source, then begin final package/review gates. No final self-referential commit/archive digest goes into committed content.
- [ ] Export that candidate commit to an empty owned directory, run `npm ci --ignore-scripts --no-audit --no-fund`, build and run `npm test`. Preserve exact count/failures; do not keep claiming 326 after adding tests. Any later shipped source/version/document change returns here with a new candidate and new package verification.
- [ ] Audit package contents before extraction/install: no traversal/links, raw reports, `.runtime`, `.tools`, research checkouts, local settings, private seeds/answers or credentials. Existing portable fixtures can remain source-only. Product modules/manifests/skills/notices must be included.
- [ ] Add installed real CLI/MCP/API tests for advertised capabilities, read-only defaults, cancellation, retained view expiry, explicit export hashes and integration-disabled behavior. Check help, setup dry-run, plugin loaders and unknown/error exits from the tarball, not root dist.
- [ ] Update the public summary whitelist explicitly for the candidate version; never allow all reports/**. Check repository-relative links and packaged README links; planning documents can use GitHub URLs without expanding the runtime tarball.
- [ ] Run `node scripts/package-smoke.mjs` using its actual reviewed arguments and `node scripts/check-release.mjs` on the staged public source. Record local tool/version/source identity and independently inspect privacy/license output.
- [ ] Commit `build: verify clean recovery distribution` with actual lock/manifest changes only.

**Acceptance:** Fresh locked build/install and actual interfaces work; no raw private evidence or undeclared vendored license appears. Package verification has a new digest/report, not reused v0.1 checks.

## Task L1: Platform/pin matrix and fresh independent review

**Files:** Extend `.github/workflows/ci.yml`; create explicitly opt-in integration/qualification workflows as needed; maintain reviewed matrix manifests under `docs/verification/`; update prerequisite-checking integration runner.

**Consumes:** L0. **Produces:** Candidate-commit CI results, exact compatibility matrix and scoped independent review closure.

- [ ] Keep portable Windows/Ubuntu lanes. Validate Node 24.16.0 product floor and 24.22.1 integration runtime with pinned actions/dependencies. Compile/build only trusted source; no target install/build hooks in CI.
- [ ] Add separate explicit optional-tool lanes: pinned original REA and reviewed second source pin; native/provider OS/ABI; runtime profiles; framework profiles. Acquire from official pinned sources/digests with scripts/credentials reviewed. No secret is exposed to untrusted PR code or target tools.
- [ ] Missing providers produce clear unavailable exits and leave the corresponding support gate unmet; they cannot silently skip to a green qualification result. Keep historical 22-test research mode distinct from new integration suites.
- [ ] Review semantics, filesystem/range accounting, worker/MCP bounds, process ownership, isolated judges and evidence interpretation independently. Review every supported-profile diff against actual source and tests, not just author summaries.
- [ ] Reproduce Important/Critical findings with failing controls, repair and rerun targeted/affected full checks. Keep original failures and accepted Minor limitations. Commit `ci: gate recovery compatibility and reviewed profiles`.

**Acceptance:** CI reports match the candidate commit, genuine claimed cells pass, unsupported cells are documented, and no Important/Critical finding is open. Mock-only success does not satisfy provider qualification.

## Task L2: Milestone evidence and claim gate

**Files:** Review the frozen version-specific sanitized summary, matrix, CHANGELOG, coverage/operation/README claims prepared before L0. Write final gate report/notes/checksums as external release assets in ignored owned output storage. If any tracked claim or verifier needs correction, commit the fix and return to L0 rather than changing a gated candidate silently.

**Consumes:** L1/B4 and the applicable J5/S5/V5/N5 gate. **Produces:** `ReleaseGateReport {candidateCommit,version,requiredTasks,checks,review,qualifiedProfiles,unknowns,artifacts,verdict}` and version-specific human-readable notes.

- [ ] Check every milestone predicate against its exact frozen cohort/fixture/provider evidence: selected task correctness, three independent seed/builds for claimed families, original identity, limits, review authority and owned cleanup. Replays do not increase independent seed counts.
- [ ] Require the v0.2 added-benefit predicate before claiming added feature recovery. Later releases distinguish large-file admission, selected bytes, typed metadata, code attribution, finite runtime agreement and collector loss behavior. Failed/unknown trials remain in denominators.
- [ ] Verify every public number/source link from structured records. Unmeasured token/cost/RSS/model fields stay null/unmeasured. No regenerated log is presented as original; publish artifact/source/pin hashes and exact scope.
- [ ] Verify concrete install/upgrade/manual-fallback instructions, experimental labels and limitations in the frozen candidate. Credit/link the original REA project and respect BLA/REA licensing; no endorsement is implied. Missing copy is a candidate change and returns to L0.
- [ ] Have a fresh reviewer inspect the final source/package/claims together. If a required gate is false, stop the release claim and record it. Do not convert the roadmap's proposed versions into completion dates or fabricate broad rates.
- [ ] Seal the final external ReleaseGateReport against the unchanged candidate commit/package digests. If reviewed evidence requires a public documentation correction, use `docs: record qualified recovery milestone evidence` and rerun L0-L2 on the new candidate before publication.

**Acceptance:** A reviewer can trace each advertised capability to actual tests/qualification. Partial functionality can ship only with an explicit narrower release scope; the full unfinished milestone remains open.

## Task L3: Version, tag, GitHub assets and final verification

**Files:** No source/version edits after L2. Use the frozen candidate commit and external release notes/checksums/verification files, not shell-built multiline strings. Any required edit invalidates candidate-dependent checks and returns to L0.

**Consumes:** L2 passing gate. **Produces:** Owner-attributed commit, new annotated tag, public GitHub release and matching source/archive/checksum/verification assets.

- [ ] Verify the frozen version, source commit, L0 tarball and L2 gate report agree. A new version/source/doc edit cannot be slipped into publication; rebuild and revalidate through L0-L2 first.
- [ ] Confirm a clean public source index, correct remote/public visibility and exact user author/committer identity. Use the existing secure GitHub session; do not print credentials, invent an email or change global Git settings. Omit AI/co-author trailers.
- [ ] Push/fast-forward the already reviewed candidate normally with no force push; required CI must pass on that exact unchanged commit. If CI requires an earlier branch push during L1, verify the same SHA here. Create a new annotated tag only after the gates pass. Never replace an existing tag or overwrite an asset to conceal a failed attempt.
- [ ] Publish the research prerelease with fresh tarball, SHA256SUMS and sanitized gate/verification manifest using a structured notes file. Record release/API URLs and actual upload results; no npm publication occurs.
- [ ] Verify remote public visibility, non-draft release state, tag target, every asset's name/size/digest, source SHA, required CI conclusions and clean local Git status. Check commits plus GitHub contributors/stats indexes for owner-only attribution; distinguish a recomputing cache from verified data.
- [ ] Record local delivery/decision/task-ledger receipts without committing private paths/raw logs. Report the actual release link and remaining unsupported scope.

**Acceptance:** The public repository, immutable tag, archive and checksum describe the same reviewed version. Success is verified remotely; a submitted push/upload command alone is insufficient.

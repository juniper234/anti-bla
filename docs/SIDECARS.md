# Explicit JavaScript inspection sidecars

`prepare_javascript_view` writes a bounded inspection view that a local static tool such as source-pinned REA can read directly. It does not execute the artifact, remove the preserved corpus or establish executable equivalence. Originals are read through the existing bounded snapshot path and never rewritten.

## Opt in

The operator must supply an **existing local workspace directory**. No workspace is inferred from an artifact, root, current directory or target content. Without it, `analysisWrites` is `false`, capabilities and MCP discovery omit the write operation, and direct requests return `workspace_required` before target reads.

```javascript
import { AnalysisService } from 'anti-bla';
const service = await AnalysisService.create({
  roots: ['C:/artifacts'],
  workspace: 'C:/analysis-views',
});
const result = await service.run('prepare_javascript_view', {
  path: 'C:/artifacts/application.mjs',
  // loader: 'js', entryExport: 'register',
  assumeStandardIntrinsics: false,
});
await service.close();
```

```powershell
anti-bla prepare-javascript-view 'C:\artifacts\application.mjs' --root 'C:\artifacts' --workspace 'C:\analysis-views'
anti-bla serve --root 'C:\artifacts' --workspace 'C:\analysis-views'
anti-bla setup --root 'C:\artifacts' --workspace 'C:\analysis-views' --dry-run
```

The optional normalizer arguments are `loader` (`js`, `jsx`, `ts`, `tsx`), `entryExport`, and `assumeStandardIntrinsics` (default `false`). CLI spelling is `--loader`, `--entry-export`, and opt-in `--assume-standard-intrinsics`. Arguments cannot select output names, paths, URLs, commands or executables. `setup` produces a concrete proposal with the exact optional `--workspace` argv; it writes no configuration or files. A trusted plugin client may configure `ANTI_BLA_WORKSPACE` for `scripts/plugin-mcp-launcher.mjs`; absence keeps the launcher read-only. An empty/invalid value is refused.

Enabled MCP discovery marks only this operation `readOnlyHint:false`, `idempotentHint:false`, `destructiveHint:false`, `openWorldHint:false`. Existing operations retain their read-only hints. Capabilities describe the actual workspace and storage bounds.

Default CLI help lists the read-only operation set. Use `anti-bla capabilities --root <root> --workspace <workspace>` to discover the enabled write operation and its scope.
The result cap also applies to capabilities: a very small caller limit combined with a long workspace path can return `output_limit` instead of a capabilities document.

## Storage and evidence

Each admitted request creates a unique `anti-bla-view-<uuid>` directory directly under the workspace, exclusively, then exclusively creates the fixed inspection filename below and `evidence.json`. Existing paths are never reused or overwritten. The response contains small locator/proof metadata in `sidecar`: absolute `viewDirectory`, `viewPath`, `evidencePath`, transaction ID, original SHA-256, derivative SHA-256/byte length, evidence SHA-256/byte length, change-map SHA-256/count, creation time, and `completion:"complete"`.

| Admitted loader | Tool-owned filename |
| --- | --- |
| omitted or `js` | `inspection.mjs` |
| `jsx` | `inspection.jsx` |
| `ts` | `inspection.ts` |
| `tsx` | `inspection.tsx` |

The loader selects from this fixed mapping; the original suffix does not choose the output name. No caller-selected output name is accepted. Syntax is preserved without transpilation, allowing REA to select the corresponding grammar. The complete locator, uncertain locator, manifest filename and preflight all use the same mapping.

Normalization runs exactly once inside the same bounded worker used by read-only analysis. `source:null` or normalizer `UNKNOWN` produces no derivative. Valid views can still contain unknown expressions and effect calls; no unsupported semantic claim is promoted by export. The preserved corpus, unrelated definitions and effect calls remain in the derivative. Standard intrinsics, reflection, self-hashes, invocation and initialization order remain explicit caveats.

The derivative cap is 8 MiB even if a smaller admitted input expands. The evidence cap is 64 KiB. The original service defaults remain: 64 MiB input, 64 KiB result JSON, five-second deadline, 128 MiB worker old-generation heap and one active analysis per service. Existing bounded limit overrides still apply; the exporter adds no automatic increases. Exact response and evidence byte sizes are preflighted before storage side effects. MCP reserves space for caller-controlled request IDs before starting a write and checks the final exact frame size.

Evidence is created **last**, after writing, syncing and rehashing the exact derivative through its open file handle. It records the original and derivative hashes/lengths, implementation/module/runtime identity, exact selection/assumptions, change-map identity/count, creation time, inspection-only scope and `fullEquivalence:"UNKNOWN"`. It contains no whole corpus or unbounded findings. The evidence file is also synced and rehashed. Its metadata is our analysis evidence; it gives no authority to embedded artifact claims.

The workspace scan streams names (32-entry buffers) and refuses after 4,096 observed entries. It counts every name beginning `anti-bla-view-`, including incomplete directories, files and links, without reading or following them. At 128 such names, requests fail `workspace_entry_limit`. An exclusive `.anti-bla-views.lock` serializes scan plus directory reservation across independent clients/processes. Pending view directories consume the same persistent cap as completed ones. The per-file lock is removed only after checking its own created identity. Nothing is silently pruned; unrelated entries are never changed. No recursive deletion or cleanup of other scratch paths occurs.

Workspace and write-parent paths must be regular non-link directories. Their canonical paths and device/inode identities are captured and checked during the transaction. Input paths for this operation also refuse links in any component and are checked against roots before filesystem reads. These are observed-change checks in an **explicitly trusted, operator-owned workspace**, not an OS filesystem sandbox against concurrent hostile writers. The caller must not grant untrusted concurrent writers access to the workspace or its parents.

## Incomplete and interrupted work

Only an `ok` response with `sidecar.completion:"complete"`, matching output/evidence hashes and a valid complete evidence record supports the intended static handoff. All error/UNKNOWN responses disallow it. Worker termination, cancellation, timeout, disk failure, a lost response or a wire failure can leave an empty directory, partial files, a complete file whose response was lost, or a reservation lock. An uncertainty response includes its intended locator with `completion:"unknown"`, `mayExist:true`, `handoffAllowed:false` when that locator fits the configured bound. These fields are conservative: the directory need not actually exist. A preflight rejection can leave no artifacts.

A missing, partial, invalid or mismatched evidence file is not a completed view. Even a syntactically complete evidence file does not upgrade an interrupted request into a successful handoff. Preserve it as uncertain evidence. A surviving reservation lock is never automatically declared stale or removed, and subsequent writes fail `workspace_busy`. An operator can inspect retained work and choose a new explicit empty workspace; any removal of retained evidence is a separate operator decision. The tool never removes view directories.

## REA handoff

After checking a successful response and both hashes, use the returned `viewDirectory` as the target for the pinned source wrapper:

```powershell
& '<isolated Node 24.22.1>\node.exe' '<pinned REA source>\scripts\rea.mjs' analyze-javascript-application '<returned viewDirectory>' --format json
```

This is static inspection of the derivative. Do not run the returned inspection file, its imports, hooks or embedded directives. REA results remain subject to their own raw status, coverage and resource limits. An exact selected call-site recovery does not establish full semantic recovery. Previously contained behavior observations apply only to byte-identical qualified derivatives; this export path itself performs no dynamic equivalence run.

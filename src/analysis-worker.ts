import { parentPort, workerData } from 'node:worker_threads';
import { createHash } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import { readSnapshot, identifyFormat, underRoot, validateLocalPath } from './artifacts.js';
import path from 'node:path';
import { indexSuspiciousData } from './poison.js';
import { AnalysisError, failure, VERSION } from './contracts.js';
import type { Limits, RecordResult } from './contracts.js';
import type { JavaScriptSection } from './javascript-view.js';
import { prepareJavaScriptView, validateSidecarInput, sidecarLocator, checkWorkspace } from './sidecars.js';
import type { WorkspaceIdentity } from './sidecars.js';

const { operation, args, roots, limits, workspace, transactionId } = workerData as {
  operation: string; args: { path: string; offset?: number; length?: number; limit?: number; memberPath?: string; maxHeaderBytes?: number; maxEntries?: number;
    loader?:'js'|'jsx'|'ts'|'tsx'; entryExport?:string; assumeStandardIntrinsics?:boolean; section?:JavaScriptSection;
    exportName?:string; table?:string; tensor?:string }; roots: string[]; limits: Limits; workspace?:WorkspaceIdentity; transactionId?:string;
};
try {
  if (operation === 'prepare_javascript_view') {
    if (!workspace || !transactionId) throw new AnalysisError('workspace_required', 'Explicit workspace required');
    validateLocalPath(args.path);
    if (!roots.some(root => underRoot(path.resolve(args.path), root))) throw new AnalysisError('outside_root', 'Outside authorized roots');
    await checkWorkspace(workspace);
    await validateSidecarInput(args.path);
  }
  const { bytes, artifact } = await readSnapshot(args.path, roots, limits);
  const implementation = createHash('sha256');
  // Fingerprint our installed parser implementation, never a target import.
  const ownDirectory = new URL('.', import.meta.url);
  const ownFiles = (await readdir(ownDirectory, { recursive: true }))
    .filter(name => name.endsWith('.js')).map(name => name.replaceAll('\\', '/')).sort();
  if (ownFiles.length > 128) throw new AnalysisError('tool_identity_limit', 'Tool identity cap', 'unknown');
  for (const name of ownFiles) {
    implementation.update(name).update(await readFile(new URL(name, ownDirectory)));
  }
  implementation.update(await readFile(new URL('../package.json', ownDirectory)));
  const analysisIdentity = { tool: 'anti-bla', version: VERSION, node: process.version,
    implementationSha256: implementation.digest('hex'), implementationModules: ownFiles };
  const { path: _sourcePath, ...selection } = args;
  const evidence = {
    schema: 'anti-bla.evidence/1', operation, input: artifact.sha256, analysisIdentity,
    selection, limits,
  };
  const evidenceId = createHash('sha256').update(JSON.stringify(evidence)).digest('hex');
  const result: RecordResult = {
    schema: 'anti-bla.result/1', operation, status: 'ok', artifact, evidenceId, evidence, analysisIdentity,
    provenance: { trust: 'untrusted-artifact', originalSha256: artifact.sha256 },
    behavioralEquivalence: 'unknown',
    limitations: [
      'Read-only static inspection; no observed execution or recovery claim.',
      'Snapshot/race checks detect observed changes; this is not an OS filesystem sandbox against concurrent hostile writers.',
    ],
  };
  if (operation === 'inspect_artifact') {
    result.identification = identifyFormat(bytes);
    result.suspiciousData = indexSuspiciousData(bytes);
    result.coverage = { identityBytes: bytes.length, semanticAnalysis: 'not-performed' };
  } else if (operation === 'read_artifact_view') {
    const offset = args.offset ?? 0;
    const requestedLength = args.length ?? 1024;
    if (offset > bytes.length) throw new AnalysisError('invalid_range', 'Offset exceeds original bytes');
    const length = Math.min(requestedLength, bytes.length - offset);
    result.view = { range: { offset, length }, base64: bytes.subarray(offset, offset + length).toString('base64'), inspectionOnly: true };
  } else if (operation === 'inspect_asar' || operation === 'read_asar_entry') {
    const { inspectAsar, readAsarEntry } = await import('./asar.js');
    const asarLimits = {
      ...(args.maxHeaderBytes === undefined ? {} : { maxHeaderBytes: args.maxHeaderBytes }),
      ...(args.maxEntries === undefined ? {} : { maxEntries: args.maxEntries }),
    };
    const analysis = operation === 'inspect_asar'
      ? inspectAsar(bytes, { ...asarLimits, offset: args.offset ?? 0, limit: args.limit ?? 20 })
      : readAsarEntry(bytes, { path: args.memberPath!, offset: args.offset ?? 0, length: args.length ?? 1024 }, asarLimits);
    result.analysis = analysis;
    result.status = analysis.status;
    if (analysis.reason !== undefined) result.reason = analysis.reason;
  } else if(operation==='inspect_javascript'||operation==='read_normalized_javascript') {
    const {javascriptInspectionView,normalizedJavaScriptView}=await import('./javascript-view.js');
    const options={...(args.loader===undefined?{}:{loader:args.loader}),...(args.entryExport===undefined?{}:{entryExport:args.entryExport}),
      assumeStandardIntrinsics:args.assumeStandardIntrinsics??false,offset:args.offset??0,
      ...(args.limit===undefined?{}:{limit:args.limit}),...(args.length===undefined?{}:{length:args.length}),
      ...(args.section===undefined?{}:{section:args.section})};
    const view=operation==='inspect_javascript'?javascriptInspectionView(bytes,options):normalizedJavaScriptView(bytes,options);
    result.analysis=view.analysis; result.status=view.status;
    if('reason' in view && view.reason!==undefined) result.reason=view.reason;
  } else if(operation === 'prepare_javascript_view') {
    const options = { ...(args.loader === undefined ? {} : { loader: args.loader }),
      ...(args.entryExport === undefined ? {} : { entryExport: args.entryExport }), assumeStandardIntrinsics: args.assumeStandardIntrinsics ?? false };
    const prepared = await prepareJavaScriptView(bytes, workspace!, transactionId!, options, limits, result);
    parentPort!.postMessage(prepared);
  } else if(['inspect_native','inspect_wasm','inspect_sqlite','inspect_model'].includes(operation)) {
    const options={offset:args.offset??0,...(args.limit===undefined?{}:{limit:args.limit})};
    let analysis:unknown;
    if(operation==='inspect_native') {
      const {inspectNative}=await import('./native.js'); analysis=inspectNative(bytes,options);
    } else {
      const {inspectWasm,inspectSqlite,inspectModel}=await import('./formats/index.js');
      analysis=operation==='inspect_wasm'?inspectWasm(bytes,{...options,...(args.exportName===undefined?{}:{exportName:args.exportName})}):
        operation==='inspect_sqlite'?inspectSqlite(bytes,{...options,...(args.table===undefined?{}:{table:args.table})}):
        inspectModel(bytes,{...options,...(args.tensor===undefined?{}:{tensor:args.tensor})});
    }
    if(typeof analysis!=='object'||analysis===null||Array.isArray(analysis)) throw new AnalysisError('invalid_adapter_result','Adapter did not return an object','unknown');
    const record=analysis as Record<string,unknown>;
    result.analysis=record;
    result.status=record.status==='ok'?'ok':record.status==='error'?'error':'unknown';
    if(record.reason!==undefined) result.reason=record.reason;
  }
  if (operation !== 'prepare_javascript_view') parentPort!.postMessage(result);
} catch (error) {
  // Never return target strings, raw parser diagnostics or local credential
  // paths through errors. Errors are classifications, not artifact authority.
  const result = error instanceof AnalysisError
    ? failure(operation, error.code, error.status)
    : failure(operation, (error as NodeJS.ErrnoException).code === 'ENOENT' ? 'not_found' : 'read_failure');
  if (operation === 'prepare_javascript_view' && workspace && transactionId) {
    const uncertain = { ...result, sidecar: { ...sidecarLocator(workspace.path, transactionId, args.loader), completion: 'unknown', mayExist: true, handoffAllowed: false } };
    parentPort!.postMessage(Buffer.byteLength(JSON.stringify(uncertain)) <= limits.maxOutputBytes ? uncertain : result);
  } else parentPort!.postMessage(result);
}

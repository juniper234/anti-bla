import { realpath, stat } from 'node:fs/promises';
import path from 'node:path';
import { Worker } from 'node:worker_threads';
import { randomUUID } from 'node:crypto';
import { operations, limitSchema, failure, VERSION, mcpFrameBudget } from './contracts.js';
import type { Limits, Operation, RecordResult } from './contracts.js';
import { validateLocalPath } from './artifacts.js';
import { validateWorkspace, sidecarLocator, SIDECAR_LIMITS } from './sidecars.js';
import type { WorkspaceIdentity } from './sidecars.js';

export class AnalysisService {
  readonly roots: readonly string[];
  readonly limits: Limits;
  readonly workspace: string | undefined;
  readonly enabledOperations: readonly Operation[];
  private active = false;
  private readonly shutdown = new AbortController();
  private constructor(roots: string[], limits: Limits, private readonly workspaceIdentity?: WorkspaceIdentity) {
    this.roots = roots; this.limits = limits; this.workspace = workspaceIdentity?.path;
    this.enabledOperations = (Object.keys(operations) as Operation[]).filter(name => name !== 'prepare_javascript_view' || this.workspace !== undefined);
  }

  static async create(options: { roots: string[]; limits?: Partial<Limits>; workspace?: string }): Promise<AnalysisService> {
    if (!Array.isArray(options.roots) || options.roots.length === 0 || options.roots.length > 16) throw new Error('Explicit roots required');
    const limits = limitSchema.parse(options.limits ?? {});
    const roots = [];
    for (const root of options.roots) {
      if (typeof root !== 'string' || root.length === 0 || root.length > 4096) throw new Error('Invalid root');
      validateLocalPath(root);
      const resolved = await realpath(path.resolve(root));
      if (!(await stat(resolved)).isDirectory()) throw new Error('Root must be a directory');
      roots.push(resolved);
    }
    const workspace = options.workspace === undefined ? undefined : await validateWorkspace(options.workspace);
    return new AnalysisService([...new Set(roots)], limits, workspace);
  }

  async close(): Promise<void> { this.shutdown.abort(); }

  async run(operation: string, args: unknown, options: { signal?: AbortSignal } = {}): Promise<RecordResult> {
    if (operation.length > 64 || !Object.hasOwn(operations, operation)) return failure('unknown', 'invalid_request');
    if (operation === 'prepare_javascript_view' && !this.workspaceIdentity) return failure(operation, 'workspace_required');
    const schema = operations[operation as Operation];
    const parsed = schema.safeParse(args);
    if (!parsed.success) return failure(operation, 'invalid_request');
    if (this.shutdown.signal.aborted || options.signal?.aborted) return failure(operation, 'cancelled', 'unknown');
    if (operation === 'capabilities') {
      const capabilities: RecordResult = {
      schema: 'anti-bla.result/1', operation, status: 'ok', behavioralEquivalence: 'unknown',
      version: VERSION, node: process.version, operations: this.enabledOperations, limits: this.limits,
      maxMcpFrameBytes: mcpFrameBudget(this.limits),
      maxConcurrentAnalyses: 1, targetExecution: false, analysisWrites: this.workspace !== undefined,
      ...(this.workspace === undefined ? {} : { writeScope: { workspace: this.workspace, operation: 'prepare_javascript_view',
        exclusiveToolOwnedChildrenOnly: true, overwrite: false, ...SIDECAR_LIMITS } }),
      semanticRecovery: 'not-qualified',
      };
      return Buffer.byteLength(JSON.stringify(capabilities)) <= this.limits.maxOutputBytes
        ? capabilities : failure(operation, 'output_limit', 'unknown');
    }
    if (this.active) return failure(operation, 'busy', 'unknown');
    const transactionId = operation === 'prepare_javascript_view' ? randomUUID() : undefined;
    const selectedLoader = 'loader' in parsed.data ? parsed.data.loader : undefined;
    const uncertainSidecar = transactionId === undefined ? undefined : { ...sidecarLocator(this.workspace!, transactionId, selectedLoader),
      completion: 'unknown', mayExist: true, handoffAllowed: false };
    const interrupted = (code: string) => ({ ...failure(operation, code, 'unknown'), ...(uncertainSidecar ? { sidecar: uncertainSidecar } : {}) });
    if (Buffer.byteLength(JSON.stringify(interrupted('worker_failure'))) > this.limits.maxOutputBytes) return failure(operation, 'output_limit', 'unknown');
    this.active = true;
    let worker: Worker | undefined;
    try {
      const result = await new Promise<RecordResult>((resolve) => {
        let settled = false;
        const signal = options.signal;
        const finish = (record: RecordResult) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          signal?.removeEventListener('abort', abort);
          this.shutdown.signal.removeEventListener('abort', abort);
          resolve(record);
        };
        const abort = () => finish(interrupted('cancelled'));
        const timer = setTimeout(() => finish(interrupted('deadline')), this.limits.timeoutMs);
        signal?.addEventListener('abort', abort, { once: true });
        this.shutdown.signal.addEventListener('abort', abort, { once: true });
        try {
          worker = new Worker(new URL('./analysis-worker.js', import.meta.url), {
            workerData: { operation, args: parsed.data, roots: this.roots, limits: this.limits, workspace: this.workspaceIdentity, transactionId },
            resourceLimits: { maxOldGenerationSizeMb: this.limits.workerHeapMb, maxYoungGenerationSizeMb: 16, stackSizeMb: 4 },
          });
          worker.once('message', (value: RecordResult) => finish(value));
          worker.once('error', () => finish(interrupted('worker_failure')));
          worker.once('exit', () => finish(interrupted('worker_exit')));
          if (signal?.aborted || this.shutdown.signal.aborted) abort();
        } catch { finish(interrupted('worker_failure')); }
      });
      if (Buffer.byteLength(JSON.stringify(result)) > this.limits.maxOutputBytes) return interrupted('output_limit');
      return result;
    } finally {
      if (worker) await worker.terminate();
      this.active = false;
    }
  }
}

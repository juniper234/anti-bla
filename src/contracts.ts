import { z } from 'zod';

export const VERSION = '0.1.0';
export const limitSchema = z.strictObject({
  maxInputBytes: z.number().int().min(1).max(256 * 1024 * 1024).default(64 * 1024 * 1024),
  maxOutputBytes: z.number().int().min(1024).max(256 * 1024).default(64 * 1024),
  timeoutMs: z.number().int().min(1).max(30_000).default(5_000),
  workerHeapMb: z.number().int().min(32).max(256).default(128),
});
export type Limits = z.infer<typeof limitSchema>;
// JSON embedded in MCP text can expand through escaping; discovery has fixed
// protocol overhead independent of the smaller artifact-record budget.
export const mcpFrameBudget = (limits: Limits): number => Math.max(16 * 1024, limits.maxOutputBytes * 2 + 4096);
const inputPath = z.string().min(1).max(4096).refine(p => !p.includes('\0'));
const asarLimits = {
  maxHeaderBytes: z.number().int().min(1).max(64 * 1024 * 1024).optional(),
  maxEntries: z.number().int().min(1).max(50_000).optional(),
};
const javascriptOptions = {
  loader:z.enum(['js','jsx','ts','tsx']).optional(),
  entryExport:z.string().min(1).max(256).optional(),
  assumeStandardIntrinsics:z.boolean().default(false),
};
const pageOptions={offset:z.number().int().min(0).max(Number.MAX_SAFE_INTEGER).default(0),limit:z.number().int().min(1).max(100).optional()};
const selector=z.string().min(1).max(4096);
export const operations = {
  capabilities: z.strictObject({}),
  inspect_artifact: z.strictObject({ path: inputPath }),
  read_artifact_view: z.strictObject({
    path: inputPath,
    offset: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER).default(0),
    length: z.number().int().min(0).max(4096).default(1024),
  }),
  inspect_asar: z.strictObject({
    path: inputPath, ...asarLimits,
    offset: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER).default(0),
    limit: z.number().int().min(1).max(100).default(20),
  }),
  read_asar_entry: z.strictObject({
    path: inputPath, memberPath: z.string().min(1).max(32768).refine(p => !p.includes('\0')), ...asarLimits,
    offset: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER).default(0),
    length: z.number().int().min(0).max(4096).default(1024),
  }),
  inspect_javascript:z.strictObject({path:inputPath,...javascriptOptions,
    section:z.enum(['summary','roots','facts','unknowns','effects','digestProofs']).default('summary'),
    offset:z.number().int().min(0).max(Number.MAX_SAFE_INTEGER).default(0),limit:z.number().int().min(1).max(100).default(20)}),
  read_normalized_javascript:z.strictObject({path:inputPath,...javascriptOptions,
    offset:z.number().int().min(0).max(Number.MAX_SAFE_INTEGER).default(0),length:z.number().int().min(0).max(32768).default(4096)}),
  prepare_javascript_view:z.strictObject({path:inputPath,...javascriptOptions}),
  inspect_native:z.strictObject({path:inputPath,...pageOptions}),
  inspect_sqlite:z.strictObject({path:inputPath,table:selector.optional(),...pageOptions}),
  inspect_wasm:z.strictObject({path:inputPath,exportName:selector.optional(),offset:pageOptions.offset,
    limit:z.number().int().min(1).max(4096).optional()}).refine(o=>o.exportName!==undefined||o.limit===undefined||o.limit<=100),
  inspect_model:z.strictObject({path:inputPath,tensor:selector.optional(),offset:pageOptions.offset,
    limit:z.number().int().min(1).max(4096).optional()}).refine(o=>o.tensor!==undefined||o.limit===undefined||o.limit<=100),
};
export type Operation = keyof typeof operations;
export type RecordResult = {
  schema: 'anti-bla.result/1';
  operation: string;
  status: 'ok' | 'unknown' | 'error';
  behavioralEquivalence: 'unknown';
  [key: string]: unknown;
};
export class AnalysisError extends Error {
  constructor(public code: string, message: string, public status: 'unknown' | 'error' = 'error') { super(message); }
}
export function failure(operation: string, code: string, status: 'unknown' | 'error' = 'error'): RecordResult {
  return { schema: 'anti-bla.result/1', operation, status, reason: { code }, behavioralEquivalence: 'unknown' };
}

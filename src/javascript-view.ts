import { createHash } from 'node:crypto';
import { inspectJavaScript, normalizeJavaScript } from './javascript.js';
import type { JavaScriptOptions } from './javascript.js';

export type JavaScriptSection = 'summary'|'roots'|'facts'|'unknowns'|'effects'|'digestProofs';
type Selection = JavaScriptOptions & {section?:JavaScriptSection; offset?:number; limit?:number; length?:number};
const sha = (bytes:string) => createHash('sha256').update(bytes).digest('hex');

export function javascriptInspectionView(bytes:Buffer, options:Selection) {
  const report=inspectJavaScript(bytes,options);
  const section=options.section??'summary';
  const offset=options.offset??0, limit=options.limit??20;
  const {roots,facts,unknowns,effects,digestProofs,...summary}=report;
  const lists={roots,facts,unknowns,effects,digestProofs};
  return {status:report.status==='OK'?'ok' as const:'unknown' as const,
    analysis:{...summary,assumeStandardIntrinsics:options.assumeStandardIntrinsics??false,
      counts:Object.fromEntries(Object.entries(lists).map(([name,list])=>[name,list.length])),
      ...(section==='summary'?{}:{page:{section,offset,limit,total:lists[section].length,
        items:lists[section].slice(offset,offset+limit),nextOffset:offset+limit<lists[section].length?offset+limit:null}})}};
}

export function normalizedJavaScriptView(bytes:Buffer, options:Selection) {
  const normalized=normalizeJavaScript(bytes,options);
  const summary={scope:normalized.scope,fullEquivalence:normalized.fullEquivalence,
    originalSha256:normalized.originalSha256,
    assumeStandardIntrinsics:options.assumeStandardIntrinsics??false,
    assumptions:normalized.analysis.assumptions,limitations:normalized.limitations,
    unknowns:normalized.analysis.unknowns.slice(0,10),effects:normalized.analysis.effects.slice(0,10),
  };
  if(normalized.source===null) return {status:'unknown' as const,analysis:{...summary,derivative:null}};
  const source=Buffer.from(normalized.source);
  const derivative={sha256:normalized.derivativeSha256,bytes:source.length};
  const offset=options.offset??0, requested=options.length??4096;
  if(offset>source.length) return {status:'error' as const,reason:{code:'invalid_range'},analysis:{...summary,derivative}};
  const length=Math.min(requested,source.length-offset);
  const mappings=normalized.changes.map(change=>({originalRange:change.range,replacementSha256:sha(change.replacement),replacementBytes:Buffer.byteLength(change.replacement)}));
  return {status:'ok' as const,analysis:{...summary,derivative,
    view:{range:{offset,length},base64:source.subarray(offset,offset+length).toString('base64'),nextOffset:offset+length<source.length?offset+length:null},
    changeMap:{total:mappings.length,sha256:sha(JSON.stringify(mappings)),entries:mappings.slice(0,20),complete:mappings.length<=20}}};
}

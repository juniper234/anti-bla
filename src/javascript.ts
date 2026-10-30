import { createHash } from 'node:crypto';
import { parse } from '@babel/parser';
import _traverse, { type NodePath } from '@babel/traverse';
import * as t from '@babel/types';
import { Evaluator, type Value } from './javascript/evaluator.js';
import { validateDigests } from './javascript/digest.js';

const traverse = (typeof _traverse === 'function' ? _traverse : _traverse.default) as typeof _traverse.default;
export interface JavaScriptOptions {
  loader?: 'js' | 'jsx' | 'ts' | 'tsx';
  entryExport?: string;
  /** Assumes standard intrinsic implementations remain unchanged during analyzed execution. */
  assumeStandardIntrinsics?: boolean;
}
export const JAVASCRIPT_LIMITS = Object.freeze({ inputBytes: 8 * 1024 * 1024, hardInputBytes: 32 * 1024 * 1024,
  astNodes: 200_000, astDepth: 512, evaluatorDepth: 64, workSteps: 500_000, primitiveStringBytes: 65_536, facts: 256, rootNameChars: 256 });
export type SourceRange = { byteStart: number; byteEnd: number; utf16Start: number; utf16End: number };
export type Finding = { reason: string; range?: SourceRange };
export type Fact = { kind: 'return' | 'call-argument' | 'predicate'; value: string | number | boolean | null; range: SourceRange; root: string; authority: string };
export interface JavaScriptInspection {
  status: 'OK' | 'UNKNOWN';
  source: { sha256: string; byteLength: number; authority: string };
  limits: typeof JAVASCRIPT_LIMITS;
  assumptions: string[];
  roots: { exportName: string; range: SourceRange }[];
  facts: Fact[];
  unknowns: Finding[];
  effects: Finding[];
  digestProofs: { range: SourceRange; corpusRange: SourceRange; digest: number; entries: number; authority: string }[];
  stats: { astNodes: number; workSteps: number; candidateProducts: number; omittedFindings: number };
  limitations: string[];
}
export class AnalysisLimit extends Error {}
export function inspectJavaScript(bytes: Buffer, options: JavaScriptOptions = {}): JavaScriptInspection {
  return analyzeJavaScript(bytes, options).report;
}
export function normalizeJavaScript(bytes: Buffer, options: JavaScriptOptions = {}) {
  const result = analyzeJavaScript(bytes, options);
  const changes: { range: SourceRange; replacement: string }[] = [];
  if (result.report.status === 'OK' && result.evaluator) {
    try {
      const byRange = new Map<string, t.Node>();
      for (const node of result.paths.keys()) byRange.set(`${node.start}:${node.end}`, node);
      for (const fact of result.report.facts) {
        const node = byRange.get(`${fact.range.utf16Start}:${fact.range.utf16End}`);
        if (!node || t.isLiteral(node)) continue;
        const value = result.evaluator.evaluate(node);
        if (value.kind !== 'constant' || !value.pure) continue;
        const replacement = Object.is(value.value, -0) ? '-0' : JSON.stringify(value.value);
        changes.push({ range: fact.range, replacement });
      }
    } catch (error) {
      result.report.status = 'UNKNOWN';
      result.report.unknowns.push({ reason: error instanceof AnalysisLimit ? error.message : 'normalization-error' });
      changes.length = 0;
    }
  }
  // Keep the outermost replacement when facts overlap. Every untouched byte stays in place.
  changes.sort((a, b) => a.range.byteStart - b.range.byteStart || b.range.byteEnd - a.range.byteEnd);
  const accepted = changes.filter((item, index) => !changes.slice(0, index).some(prev => prev.range.byteStart <= item.range.byteStart && prev.range.byteEnd >= item.range.byteEnd));
  let source = result.source;
  for (const change of [...accepted].reverse()) source = source.slice(0, change.range.utf16Start) + change.replacement + source.slice(change.range.utf16End);
  const admittedSource = result.report.status === 'OK' ? source : null;
  return { source: admittedSource, analysis: result.report, changes: accepted, scope: 'inspection-only' as const, fullEquivalence: 'UNKNOWN' as const,
    originalSha256: result.report.source.sha256, derivativeSha256: admittedSource === null ? null : createHash('sha256').update(admittedSource).digest('hex'),
    limitations: ['Derivative retains unrelated definitions, digest corpus and heap/global effect calls. It is a source-indexed analysis view, not an execution-equivalent replacement.', 'Runtime or source self-hashes, reflection and invocation/initialization order can distinguish this view.'] };
}
/** Internal analysis state is never returned by the public inspector. */
export function analyzeJavaScript(bytes: Buffer, options: JavaScriptOptions = {}) {
  const report: JavaScriptInspection = {
    status: 'OK', source: { sha256: createHash('sha256').update(bytes).digest('hex'), byteLength: bytes.length, authority: 'untrusted artifact; hash establishes byte identity only' },
    limits: JAVASCRIPT_LIMITS,
    assumptions: ['Facts describe expression values on normal completion, not termination, absence of effects, or whole-program equivalence.', ...(options.assumeStandardIntrinsics ? ['Standard intrinsics remain unmodified during analyzed execution; detected shadowing, escape or writes invalidate intrinsic proofs.'] : [])],
    roots: [], facts: [], unknowns: [], effects: [], digestProofs: [],
    stats: { astNodes: 0, workSteps: 0, candidateProducts: 0, omittedFindings: 0 },
    limitations: ['No target code, getters, imports, eval or dynamic calls execute.', 'No original symbol-name restoration; reflective dispatch, object/getter aliases and unresolved calls remain unknown.', 'Entry roots are syntactic exports; invocation and module initialization are not proven. Unrelated definitions are not summarized.'],
  };
  let source = '';
  let ast: t.File | undefined;
  let evaluator: Evaluator | undefined;
  const paths = new Map<t.Node, NodePath>();
  let byteOffsets = new Uint32Array(0);
  const range = (node: t.Node): SourceRange => ({ byteStart: byteOffsets[node.start ?? 0] ?? 0, byteEnd: byteOffsets[node.end ?? 0] ?? 0,
    utf16Start: node.start ?? 0, utf16End: node.end ?? 0 });
  const finding = (list: Finding[], reason: string, node?: t.Node) => {
    if (list.length < JAVASCRIPT_LIMITS.facts) list.push({ reason, ...(node ? { range: range(node) } : {}) });
    else { report.stats.omittedFindings++; report.status = 'UNKNOWN'; }
  };
  const unknown = (reason: string, node?: t.Node) => finding(report.unknowns, reason, node);
  const effect = (reason: string, node?: t.Node) => finding(report.effects, reason, node);
  const tick = () => { if (++report.stats.workSteps > JAVASCRIPT_LIMITS.workSteps) throw new AnalysisLimit('work-step-limit'); };
  try {
    if (bytes.length > JAVASCRIPT_LIMITS.inputBytes) throw new AnalysisLimit('input-byte-limit');
    if (options.entryExport !== undefined && (typeof options.entryExport !== 'string' || options.entryExport.length > JAVASCRIPT_LIMITS.rootNameChars)) throw new AnalysisLimit('entry-export-name-limit');
    if (options.loader !== undefined && !['js', 'jsx', 'ts', 'tsx'].includes(options.loader)) throw new AnalysisLimit('invalid-loader');
    source = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
    byteOffsets = new Uint32Array(source.length + 1);
    for (let i = 0, b = 0; i < source.length;) {
      byteOffsets[i] = b;
      const cp = source.codePointAt(i)!;
      const chars = cp > 0xffff ? 2 : 1;
      if (chars === 2) byteOffsets[i + 1] = b;
      b += cp <= 0x7f ? 1 : cp <= 0x7ff ? 2 : cp <= 0xffff ? 3 : 4;
      i += chars; byteOffsets[i] = b;
    }
    ast = parse(source, { sourceType: 'unambiguous', errorRecovery: false,
      plugins: [...(options.loader === 'ts' || options.loader === 'tsx' ? ['typescript' as const] : []), ...(options.loader === 'jsx' || options.loader === 'tsx' ? ['jsx' as const] : [])] });
    const stack: [t.Node, number][] = [[ast, 0]];
    while (stack.length) {
      const [node, depth] = stack.pop()!;
      if (++report.stats.astNodes > JAVASCRIPT_LIMITS.astNodes) throw new AnalysisLimit('ast-node-limit');
      if (depth > JAVASCRIPT_LIMITS.astDepth) throw new AnalysisLimit('ast-depth-limit');
      for (const key of t.VISITOR_KEYS[node.type] ?? []) {
        const child = (node as unknown as Record<string, unknown>)[key];
        if (Array.isArray(child)) { for (const n of child) if (n?.type) stack.push([n, depth + 1]); }
        else if (child && typeof child === 'object' && 'type' in child) stack.push([child as t.Node, depth + 1]);
      }
    }
    let intrinsicallyUnsafe = false;
    let dynamicallyScoped = false;
    traverse(ast, { enter(path) {
      tick(); paths.set(path.node, path);
      if (path.isWithStatement()) { intrinsicallyUnsafe = true; dynamicallyScoped = true; unknown('dynamic-scope', path.node); }
      if ((path.isCallExpression() || path.isNewExpression()) && t.isIdentifier(path.node.callee) && ['eval', 'Function'].includes(path.node.callee.name)) {
        intrinsicallyUnsafe = true; dynamicallyScoped = true; unknown('dynamic-evaluation', path.node);
      }
      if (path.isMemberExpression() && t.isIdentifier(path.node.object) && ['globalThis', 'global', 'window', 'self'].includes(path.node.object.name) && !path.scope.getBinding(path.node.object.name)) {
        const key = !path.node.computed && t.isIdentifier(path.node.property) ? path.node.property.name : t.isStringLiteral(path.node.property) ? path.node.property.value : undefined;
        if (key === undefined || ['Math', 'Array', 'String', 'Number'].includes(key)) intrinsicallyUnsafe = true;
      }
      if (path.isIdentifier() && path.isReferencedIdentifier() && ['Math', 'Array', 'String', 'Number'].includes(path.node.name) && !path.scope.getBinding(path.node.name)) {
        const parent = path.parentPath;
        // Only direct property reads used as callees are accepted. Aliases and mutation are conservatively unsafe.
        const directConversion = ['Number', 'String'].includes(path.node.name) && parent.isCallExpression() && parent.node.callee === path.node;
        const constructor = parent.isNewExpression() && parent.node.callee === path.node && ['Array', 'Number', 'String'].includes(path.node.name);
        if (!directConversion && !constructor && (!parent.isMemberExpression() || parent.node.object !== path.node || !parent.parentPath.isCallExpression() || parent.parentPath.node.callee !== parent.node)) intrinsicallyUnsafe = true;
      }
    } });
    // Babel lexical bindings do not model with lookup or names introduced by sloppy eval.
    // Refuse value proofs for this file while retaining inert syntax/effect observations.
    if (dynamicallyScoped) report.status = 'UNKNOWN';
    evaluator = new Evaluator({ paths, tick, limits: JAVASCRIPT_LIMITS, proofsAllowed: !dynamicallyScoped, intrinsics: options.assumeStandardIntrinsics === true && !intrinsicallyUnsafe });
    validateDigests(evaluator, (call, corpus, digest, entries) => {
      if (report.digestProofs.length >= JAVASCRIPT_LIMITS.facts) throw new AnalysisLimit('digest-proof-limit');
      report.digestProofs.push({ range: range(call), corpusRange: range(corpus), digest, entries, authority: 'exact binding-resolved helper structure and inert literal corpus calculation; no marker authority' });
    });
    const roots: { name: string; node: t.Node; resolved: boolean }[] = [];
    const addRoot = (name: string, original: t.Node) => {
      if (options.entryExport !== undefined && options.entryExport !== name) return;
      if (name.length > JAVASCRIPT_LIMITS.rootNameChars) throw new AnalysisLimit('root-name-limit');
      let node = original; let resolved = true; const visited = new Set<t.Node>();
      while (t.isIdentifier(node) && !visited.has(node)) {
        tick(); visited.add(node);
        if (visited.size > JAVASCRIPT_LIMITS.evaluatorDepth) throw new AnalysisLimit('root-alias-depth-limit');
        const binding = paths.get(node)?.scope.getBinding(node.name);
        if (!binding?.constant || !(binding.path.isFunctionDeclaration() || binding.path.isVariableDeclarator())) { resolved = false; break; }
        node = binding.path.node;
      }
      // Named export specifiers and direct export declarations enter here as declarations,
      // so they need the same binding check as identifier-based roots.
      if ((t.isVariableDeclarator(node) || t.isFunctionDeclaration(node) || t.isClassDeclaration(node)) && node.id) {
        if (!t.isIdentifier(node.id)) resolved = false;
        else {
          const binding = paths.get(node)?.scope.getBinding(node.id.name);
          if (!binding?.constant || t.isVariableDeclarator(node) && binding.kind !== 'const') resolved = false;
        }
      }
      if (!resolved) { report.status = 'UNKNOWN'; unknown('unresolved-export-binding', original); }
      roots.push({ name, node, resolved });
    };
    for (const stmt of ast.program.body) {
      if (t.isExportDefaultDeclaration(stmt)) addRoot('default', stmt.declaration);
      if (t.isExportNamedDeclaration(stmt)) {
        if (stmt.declaration) {
          if (t.isFunctionDeclaration(stmt.declaration) || t.isClassDeclaration(stmt.declaration)) { if (stmt.declaration.id) addRoot(stmt.declaration.id.name, stmt.declaration); }
          else if (t.isVariableDeclaration(stmt.declaration)) for (const decl of stmt.declaration.declarations) if (t.isIdentifier(decl.id)) addRoot(decl.id.name, decl);
        }
        for (const spec of stmt.specifiers) if (t.isExportSpecifier(spec)) {
          const binding = paths.get(spec)?.scope.getBinding(spec.local.name);
          if (binding) addRoot(t.isIdentifier(spec.exported) ? spec.exported.name : spec.exported.value, binding.path.node);
        }
      }
      if (t.isExpressionStatement(stmt) && t.isAssignmentExpression(stmt.expression, { operator: '=' }) && t.isMemberExpression(stmt.expression.left)) {
        const member = stmt.expression.left, path = paths.get(member)!;
        const key = !member.computed && t.isIdentifier(member.property) ? member.property.name : t.isStringLiteral(member.property) ? member.property.value : undefined;
        if (!key) continue;
        if (t.isIdentifier(member.object, { name: 'exports' }) && !path.scope.getBinding('exports')) addRoot(key, stmt.expression.right);
        else if (t.isMemberExpression(member.object) && t.isIdentifier(member.object.object, { name: 'module' }) && !member.object.computed && t.isIdentifier(member.object.property, { name: 'exports' }) && !path.scope.getBinding('module')) addRoot(key, stmt.expression.right);
        else if (t.isIdentifier(member.object, { name: 'module' }) && key === 'exports' && !path.scope.getBinding('module')) addRoot('default', stmt.expression.right);
      }
    }
    if (options.entryExport !== undefined && !roots.length) { report.status = 'UNKNOWN'; unknown('entry-export-not-found'); }
    if (roots.length > JAVASCRIPT_LIMITS.facts) throw new AnalysisLimit('root-limit');
    const rootCounts = new Map<string, number>();
    for (const root of roots) rootCounts.set(root.name, (rootCounts.get(root.name) ?? 0) + 1);
    for (const root of roots) if ((rootCounts.get(root.name) ?? 0) > 1) {
      root.resolved = false; report.status = 'UNKNOWN'; unknown('multiple-export-definitions', root.node);
    }
    const addFact = (kind: Fact['kind'], value: Value, node: t.Node, root: string) => {
      if (value.kind !== 'constant') return false;
      if (report.facts.length >= JAVASCRIPT_LIMITS.facts) throw new AnalysisLimit('fact-limit');
      report.facts.push({ kind, value: value.value, range: range(node), root, authority: 'binding-resolved inert AST proof under stated assumptions' }); return true;
    };
    for (const root of roots) {
      report.roots.push({ exportName: root.name, range: range(root.node) });
      if (!root.resolved) continue;
      const pending: [t.Node, boolean][] = [[root.node, true]];
      while (pending.length) {
        tick(); const [node, isRoot] = pending.pop()!;
        if (!isRoot && t.isFunction(node)) continue;
        if (t.isReturnStatement(node) && node.argument) {
          if (!addFact('return', evaluator.evaluate(node.argument), node.argument, root.name)) unknown('unresolved-return', node.argument);
        }
        if (t.isArrowFunctionExpression(node) && !t.isBlockStatement(node.body)) {
          if (!addFact('return', evaluator.evaluate(node.body), node.body, root.name)) unknown('unresolved-return', node.body);
        }
        if (t.isIfStatement(node)) {
          const value = evaluator.evaluate(node.test);
          if (value.kind === 'constant') {
            addFact('predicate', value, node.test, root.name);
            const selected = value.value ? node.consequent : node.alternate;
            if (selected) pending.push([selected, false]);
            // A known normal-completion value does not make its computation pure.
            // Visit the evaluated test before the selected branch; prune only the other branch.
            pending.push([node.test, false]);
            continue;
          }
        }
        if (t.isCallExpression(node) || t.isOptionalCallExpression(node)) {
          const value = evaluator.evaluate(node);
          if (value.kind === 'unknown') { effect('unresolved-call-may-have-effects', node); }
          node.arguments.forEach(arg => { if (t.isExpression(arg)) { const v = evaluator!.evaluate(arg); if (v.kind === 'constant' && typeof v.value === 'string') addFact('call-argument', v, arg, root.name); } });
          if (t.isMemberExpression(node.callee) && t.isIdentifier(node.callee.object, { name: 'Reflect' })) unknown('reflection-or-accessor', node);
        }
        if (t.isMemberExpression(node) || t.isOptionalMemberExpression(node)) unknown('reflection-or-accessor', node);
        if (t.isAssignmentExpression(node) || t.isUpdateExpression(node) || t.isAwaitExpression(node) || t.isYieldExpression(node)) effect('write-or-control-effect', node);
        for (const key of [...(t.VISITOR_KEYS[node.type] ?? [])].reverse()) {
          const child = (node as unknown as Record<string, unknown>)[key];
          if (Array.isArray(child)) { for (let i = child.length - 1; i >= 0; i--) if (child[i]?.type) pending.push([child[i], false]); }
          else if (child && typeof child === 'object' && 'type' in child) pending.push([child as t.Node, isRoot && t.isVariableDeclarator(node) && key === 'init']);
        }
      }
    }
  } catch (error) {
    report.status = 'UNKNOWN'; unknown(error instanceof AnalysisLimit ? error.message : error instanceof RangeError ? 'parser-or-traversal-depth-limit' : error instanceof TypeError && !source ? 'invalid-utf8' : 'syntax-or-analysis-error');
  }
  return { report, ast, paths, evaluator, source, range };
}

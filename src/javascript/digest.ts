import { parse } from '@babel/parser';
import _traverse, { type Binding, type NodePath } from '@babel/traverse';
import * as t from '@babel/types';
import type { Evaluator } from './evaluator.js';

const traverse = (typeof _traverse === 'function' ? _traverse : _traverse.default) as typeof _traverse.default;
// This trusted structural template is matched inertly, never executed. Every operator, branch,
// constant, property and binding must match; names and formatting have no authority.
const templateSource = (count: number) => `const corpus=[];function digest(seedInput=0){
if(!Array.isArray(corpus)||corpus.length<${count})return 0;
let acc=((seedInput|0)^0x26b5c67b)>>>0;
for(let i=0;i<corpus.length;i++){
const entry=corpus[i];
if(!entry||typeof entry.coupledAnchorSymbol!=="string"||typeof entry.triggerPayload!=="string")return 0;
const text=entry.coupledAnchorSymbol+"::"+entry.triggerPayload;
for(let j=0;j<text.length;j++){
acc=Math.imul(acc^text.charCodeAt(j),0x85ebca6b)>>>0;
acc=((acc<<13)|(acc>>>19))>>>0;
}}
return acc>>>0;}`;

function canonical(node: t.Node, paths: Map<t.Node, NodePath>, corpus: Binding, tick: () => void) {
  const locals = new Map<Binding, number>();
  const visit = (n: t.Node): unknown => {
    tick();
    if (t.isIdentifier(n)) {
      const path = paths.get(n);
      if (path && (path.isReferencedIdentifier() || path.isBindingIdentifier())) {
        const binding = path.scope.getBinding(n.name);
        // A binding role is not an identifier spelling: target globals can use any name.
        if (binding === corpus) return ['CorpusBinding'];
        if (binding) {
          if ((binding.path.node.start ?? -1) < (node.start ?? 0) || (binding.path.node.end ?? Infinity) > (node.end ?? 0)) return ['External', n.name];
          if (!locals.has(binding)) locals.set(binding, locals.size);
          return ['Binding', locals.get(binding)];
        }
      }
      return ['Identifier', n.name];
    }
    const keys = Object.keys(t.NODE_FIELDS[n.type] ?? {}).sort();
    const result: unknown[] = [n.type];
    for (const key of keys) {
      const val = (n as unknown as Record<string, unknown>)[key];
      if (val === undefined || val === null || val === false || Array.isArray(val) && !val.length) continue;
      if (Array.isArray(val)) result.push([key, val.map(v => v && typeof v === 'object' && 'type' in v ? visit(v as t.Node) : v)]);
      else result.push([key, val && typeof val === 'object' && 'type' in val ? visit(val as t.Node) : val]);
    }
    return result;
  };
  return JSON.stringify(visit(node));
}

export function validateDigests(evaluator: Evaluator, onProof: (call: t.Node, corpus: t.Node, digest: number, entries: number) => void) {
  if (!evaluator.context.intrinsics) return;
  const { paths, tick } = evaluator.context;
  const checked = new Map<t.FunctionDeclaration, { digest: number; corpus: t.Node; entries: number } | null>();
  const patterns = new Map<number, string>();
  for (const [node, path] of paths) {
    tick();
    if (!t.isCallExpression(node) || !t.isIdentifier(node.callee) || node.arguments.length !== 1 || !t.isNumericLiteral(node.arguments[0], { value: 0 })) continue;
    const fn = path.scope.getBinding(node.callee.name);
    if (!fn?.constant || !fn.path.isFunctionDeclaration()) continue;
    const decl = fn.path.node;
    if (!checked.has(decl)) {
      checked.set(decl, null);
      const first = decl.body.body[0];
      if (!t.isIfStatement(first) || !t.isLogicalExpression(first.test, { operator: '||' }) || !t.isUnaryExpression(first.test.left, { operator: '!' }) || !t.isCallExpression(first.test.left.argument)) continue;
      const arrayCheck = first.test.left.argument;
      if (!evaluator.isIntrinsic(arrayCheck, 'Array', 'isArray') || !t.isIdentifier(arrayCheck.arguments[0])) continue;
      const corpusBinding = paths.get(arrayCheck)?.scope.getBinding(arrayCheck.arguments[0].name);
      if (!corpusBinding?.constant || corpusBinding.kind !== 'const' || !corpusBinding.path.isVariableDeclarator() || !t.isArrayExpression(corpusBinding.path.node.init)) continue;
      const corpus = corpusBinding.path.node.init;
      if (!corpus.elements.length || corpus.elements.length > evaluator.context.limits.facts) continue;
      // Any use outside the exact matched helper could alias/mutate this object graph.
      if (corpusBinding.referencePaths.some(ref => (ref.node.start ?? -1) < (decl.start ?? 0) || (ref.node.end ?? Infinity) > (decl.end ?? 0))) continue;
      if ((corpusBinding.path.node.end ?? Infinity) >= (node.start ?? 0)) continue;
      if (fn.referencePaths.some(ref => !(ref.parentPath?.isUnaryExpression({ operator: 'typeof' }) || ref.parentPath?.isCallExpression() && ref.parentPath.node.callee === ref.node))) continue;
      let pattern = patterns.get(corpus.elements.length);
      if (!pattern) {
        const template = parse(templateSource(corpus.elements.length)); const templatePaths = new Map<t.Node, NodePath>();
        traverse(template, { enter(p) { tick(); templatePaths.set(p.node, p); } });
        const templateFn = template.program.body[1] as t.FunctionDeclaration;
        const templateCorpus = templatePaths.get(templateFn)!.scope.getBinding('corpus')!;
        pattern = canonical(templateFn, templatePaths, templateCorpus, tick); patterns.set(corpus.elements.length, pattern);
      }
      if (canonical(decl, paths, corpusBinding, tick) !== pattern) continue;
      let digest = 0x26b5c67b; let valid = true;
      for (const entry of corpus.elements) {
        if (!t.isObjectExpression(entry)) { valid = false; break; }
        const fields = new Map<string, string>();
        for (const field of entry.properties) {
          tick();
          if (!t.isObjectProperty(field) || field.computed || !t.isStringLiteral(field.value) || !(t.isIdentifier(field.key) || t.isStringLiteral(field.key))) { valid = false; break; }
          const key = t.isIdentifier(field.key) ? field.key.name : field.key.value;
          if (key === '__proto__' || fields.has(key)) { valid = false; break; }
          fields.set(key, field.value.value);
        }
        if (!valid || !fields.has('coupledAnchorSymbol') || !fields.has('triggerPayload')) { valid = false; break; }
        const text = fields.get('coupledAnchorSymbol')! + '::' + fields.get('triggerPayload')!;
        if (Buffer.byteLength(text) > evaluator.context.limits.primitiveStringBytes) { valid = false; break; }
        for (let j = 0; j < text.length; j++) { tick(); digest = Math.imul(digest ^ text.charCodeAt(j), 0x85ebca6b) >>> 0; digest = ((digest << 13) | (digest >>> 19)) >>> 0; }
      }
      if (valid) checked.set(decl, { digest, corpus, entries: corpus.elements.length });
    }
    const proof = checked.get(decl);
    if (proof) { evaluator.digestValues.set(node, proof.digest); onProof(node, proof.corpus, proof.digest, proof.entries); }
  }
}

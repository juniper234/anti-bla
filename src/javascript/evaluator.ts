import type { NodePath } from '@babel/traverse';
import * as t from '@babel/types';
import { AnalysisLimit, type JAVASCRIPT_LIMITS } from '../javascript.js';

type Primitive = string | number | boolean | null;
export type Value = { kind: 'constant'; value: Primitive; pure: boolean } | { kind: 'int'; mask: number; bits: number; pure: boolean } | { kind: 'unknown'; pure: false };
const U: Value = { kind: 'unknown', pure: false };
const C = (value: Primitive, pure = true): Value => typeof value === 'number' && !Number.isFinite(value) ? U : { kind: 'constant', value, pure };
const I = (mask: number, bits: number, pure = false): Value => (mask >>> 0) === 0xffffffff ? C(bits | 0, pure) : { kind: 'int', mask: mask >>> 0, bits: (bits & mask) >>> 0, pure };
function bits(value: Value): { mask: number; bits: number } {
  if (value.kind === 'int') return value;
  if (value.kind === 'constant') return { mask: 0xffffffff, bits: Number(value.value) >>> 0 };
  return { mask: 0, bits: 0 };
}
export interface EvaluationContext {
  paths: Map<t.Node, NodePath>; tick(): void; limits: typeof JAVASCRIPT_LIMITS; intrinsics: boolean; proofsAllowed: boolean;
}
/** No candidate sets or invocation of target-supplied values. Known bits are a constant-size domain. */
export class Evaluator {
  readonly cache = new Map<t.Node, Value>();
  readonly digestValues = new Map<t.Node, number>();
  constructor(readonly context: EvaluationContext) {}
  evaluate(node: t.Node, depth = 0, visiting = new Set<t.Node>()): Value {
    this.context.tick();
    if (!this.context.proofsAllowed) return U;
    if (depth > this.context.limits.evaluatorDepth) throw new AnalysisLimit('evaluator-depth-limit');
    const cached = this.cache.get(node); if (cached) return cached;
    if (visiting.has(node)) return U;
    visiting.add(node);
    const ev = (n: t.Node) => this.evaluate(n, depth + 1, visiting);
    let value: Value = U;
    if (t.isStringLiteral(node)) value = this.string(node.value);
    else if (t.isNumericLiteral(node) || t.isBooleanLiteral(node)) value = C(node.value);
    else if (t.isNullLiteral(node)) value = C(null);
    else if (t.isIdentifier(node)) {
      const binding = this.context.paths.get(node)?.scope.getBinding(node.name);
      if (binding?.constant && binding.kind === 'const' && binding.path.isVariableDeclarator() && binding.path.node.init &&
          (binding.path.node.end ?? Infinity) < (node.start ?? 0)) {
        const resolved = ev(binding.path.node.init);
        value = resolved.kind === 'unknown' ? U : { ...resolved, pure: true };
      }
    } else if (t.isUnaryExpression(node)) {
      if (node.operator === 'typeof' && t.isIdentifier(node.argument)) {
        const binding = this.context.paths.get(node.argument)?.scope.getBinding(node.argument.name);
        if (binding?.constant && binding.path.isFunctionDeclaration()) value = C('function');
      }
      if (value.kind === 'unknown') {
        const v = ev(node.argument);
        if (v.kind === 'constant') {
          switch (node.operator) {
            case '!': value = C(!v.value, v.pure); break;
            case '+': value = C(Number(v.value), v.pure); break;
            case '-': value = C(-Number(v.value), v.pure); break;
            case '~': value = C(~Number(v.value), v.pure); break;
            case 'typeof': value = C(typeof v.value, v.pure); break;
          }
        } else if (node.operator === '~') { const b = bits(v); value = I(b.mask, ~b.bits, v.pure); }
      }
    } else if (t.isBinaryExpression(node)) {
      const a = ev(node.left), b = ev(node.right);
      value = this.binary(node.operator, a, b);
    } else if (t.isLogicalExpression(node)) {
      const a = ev(node.left);
      if (a.kind === 'constant') {
        const takeRight = node.operator === '&&' ? !!a.value : node.operator === '||' ? !a.value : a.value === null;
        value = takeRight ? ev(node.right) : a;
        if (value.kind !== 'unknown') value = { ...value, pure: a.pure && value.pure };
      }
    } else if (t.isConditionalExpression(node)) {
      const test = ev(node.test);
      if (test.kind === 'constant') { value = ev(test.value ? node.consequent : node.alternate); if (value.kind !== 'unknown') value = { ...value, pure: test.pure && value.pure }; }
    } else if (t.isTemplateLiteral(node)) {
      let text = ''; let pure = true; let valid = true;
      for (let i = 0; i < node.quasis.length; i++) {
        const quasi = node.quasis[i]!.value.cooked; if (quasi === null) { valid = false; break; }
        text += quasi;
        if (i < node.expressions.length) { const v = ev(node.expressions[i]!); if (v.kind !== 'constant') { valid = false; break; } text += String(v.value); pure &&= v.pure; }
        if (text.length > this.context.limits.primitiveStringBytes) throw new AnalysisLimit('primitive-string-limit');
      }
      if (valid) value = this.string(text, pure);
    } else if (t.isCallExpression(node)) {
      const digest = this.digestValues.get(node); if (digest !== undefined) value = C(digest, false);
      else if (this.isIntrinsic(node, 'String', 'fromCharCode') || this.isIntrinsic(node, 'String', 'fromCodePoint')) {
        const codePoints = t.isMemberExpression(node.callee) && t.isIdentifier(node.callee.property, { name: 'fromCodePoint' });
        let text = ''; let pure = true; let valid = true;
        for (const arg of node.arguments) {
          if (!t.isExpression(arg)) { valid = false; break; }
          const v = ev(arg);
          if (v.kind !== 'constant' || typeof v.value !== 'number' || codePoints && (!Number.isInteger(v.value) || v.value < 0 || v.value > 0x10ffff)) { valid = false; break; }
          text += codePoints ? String.fromCodePoint(v.value) : String.fromCharCode(v.value); pure &&= v.pure;
          if (text.length > this.context.limits.primitiveStringBytes) throw new AnalysisLimit('primitive-string-limit');
        }
        if (valid) value = this.string(text, pure);
      }
      else if (this.isIntrinsic(node, 'Math', 'imul') && node.arguments.length === 2 && t.isExpression(node.arguments[0]) && t.isExpression(node.arguments[1])) {
        const left = node.arguments[0], right = node.arguments[1];
        const a = ev(left), b = ev(right);
        if (a.kind === 'constant' && b.kind === 'constant') value = C(Math.imul(Number(a.value), Number(b.value)), a.pure && b.pure);
        else {
          const ab = bits(a), bb = bits(b);
          const consecutive = t.isBinaryExpression(right, { operator: '+' }) && t.isNumericLiteral(right.right, { value: 1 }) && this.sameNumeric(left, right.left);
          const pure = a.pure && (b.pure || consecutive);
          if (this.sameNumeric(left, right) && (ab.mask & 1) && (ab.bits & 1)) value = I(7, 1, pure);
          else if (this.sameNumeric(left, right) && (ab.mask & 3) === 3) value = I(7, Math.imul(ab.bits, ab.bits) & 7, pure);
          else if (consecutive) value = I(1, 0, pure);
          else if ((ab.mask & 1) && (bb.mask & 1)) value = I(1, ab.bits & bb.bits & 1, pure);
          else value = I(0, 0, pure);
        }
      }
    } else if (t.isTSAsExpression(node) || t.isTSTypeAssertion(node) || t.isTSNonNullExpression(node)) value = ev(node.expression);
    visiting.delete(node); this.cache.set(node, value); return value;
  }
  isIntrinsic(node: t.CallExpression, owner: string, method: string) {
    return this.context.intrinsics && t.isMemberExpression(node.callee) && !node.callee.computed && t.isIdentifier(node.callee.object, { name: owner }) &&
      t.isIdentifier(node.callee.property, { name: method }) && !this.context.paths.get(node.callee.object)?.scope.getBinding(owner);
  }
  private string(value: string, pure = true): Value {
    if (Buffer.byteLength(value) > this.context.limits.primitiveStringBytes) throw new AnalysisLimit('primitive-string-limit');
    return C(value, pure);
  }
  private sameNumeric(a: t.Node, b: t.Node, depth = 0): boolean {
    this.context.tick(); if (depth > this.context.limits.evaluatorDepth) throw new AnalysisLimit('evaluator-depth-limit');
    if (t.isNumericLiteral(a) && t.isNumericLiteral(b)) return a.value === b.value;
    if (t.isIdentifier(a) && t.isIdentifier(b)) {
      const ba = this.context.paths.get(a)?.scope.getBinding(a.name), bb = this.context.paths.get(b)?.scope.getBinding(b.name);
      if (!ba || ba !== bb || !ba.constant) return false;
      const v = this.evaluate(a);
      return v.kind === 'int' || v.kind === 'constant' && typeof v.value === 'number';
    }
    if (t.isBinaryExpression(a) && t.isBinaryExpression(b) && ['|', '&', '^', '>>', '>>>', '<<'].includes(a.operator) && a.operator === b.operator) {
      const sameOperand = (x: t.Node, y: t.Node): boolean => {
        if (t.isIdentifier(x) && t.isIdentifier(y)) {
          const bx = this.context.paths.get(x)?.scope.getBinding(x.name);
          const v = this.evaluate(x); return !!bx && bx === this.context.paths.get(y)?.scope.getBinding(y.name) && bx.constant && v.kind !== 'unknown';
        }
        return this.sameNumeric(x, y, depth + 1);
      };
      return sameOperand(a.left, b.left) && sameOperand(a.right, b.right);
    }
    return false;
  }
  private binary(op: string, a: Value, b: Value): Value {
    const pure = a.pure && b.pure;
    if (a.kind === 'constant' && b.kind === 'constant') {
      const x = a.value, y = b.value;
      switch (op) {
        case '+': return typeof x === 'string' || typeof y === 'string' ? this.string(String(x) + String(y), pure) : C(Number(x) + Number(y), pure);
        case '-': return C(Number(x) - Number(y), pure); case '*': return C(Number(x) * Number(y), pure);
        case '/': return C(Number(x) / Number(y), pure); case '%': return C(Number(x) % Number(y), pure);
        case '===': return C(x === y, pure); case '!==': return C(x !== y, pure);
        case '<': return C(typeof x === 'string' && typeof y === 'string' ? x < y : Number(x) < Number(y), pure);
        case '>': return C(typeof x === 'string' && typeof y === 'string' ? x > y : Number(x) > Number(y), pure);
        case '<=': return C(typeof x === 'string' && typeof y === 'string' ? x <= y : Number(x) <= Number(y), pure);
        case '>=': return C(typeof x === 'string' && typeof y === 'string' ? x >= y : Number(x) >= Number(y), pure);
        case '|': return C(Number(x) | Number(y), pure); case '&': return C(Number(x) & Number(y), pure); case '^': return C(Number(x) ^ Number(y), pure);
        case '<<': return C(Number(x) << Number(y), pure); case '>>': return C(Number(x) >> Number(y), pure); case '>>>': return C(Number(x) >>> Number(y), pure);
      }
    }
    const x = bits(a), y = bits(b);
    if (op === '&') { const zero = ((x.mask & ~x.bits) | (y.mask & ~y.bits)) >>> 0; const one = x.mask & x.bits & y.mask & y.bits; return I(zero | one, one, pure); }
    if (op === '|') { const one = (x.mask & x.bits) | (y.mask & y.bits); const zero = x.mask & ~x.bits & y.mask & ~y.bits; return I(one | zero, one, pure); }
    if (op === '^') return I(x.mask & y.mask, x.bits ^ y.bits, pure);
    return U;
  }
}

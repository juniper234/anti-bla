import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';

// Inspect the Git index: the files that can actually be committed and pushed.
// Errors name a file/classification and never print a potential secret value.
const root = path.resolve(import.meta.dirname, '..');
const files = execFileSync('git', ['ls-files', '-z'], { cwd: root, encoding: 'utf8' }).split('\0').filter(Boolean);
assert.ok(files.length > 0, 'Stage the public files before checking a release.');
const fileSet = new Set(files), errors = [];
let bytes = 0;
const forbidden = /^(?:\.tools|\.runtime|\.superpowers|research|scratch|local-install|incoming|analysis-views|artifacts|node_modules|dist)(?:\/|$)|^(?:STATE\.json|WORKLOG\.md|DECISIONS\.md)$|^docs\/(?:local\/|DESIGN\.md$|IMPLEMENTATION-PLAN\.md$|ACCEPTANCE\.json$|.*-TASK-BRIEF\.md$)/;
const allowedReports = new Set(['reports/README.md', 'reports/v0.1-summary.json']);
const blob = file => execFileSync('git', ['show', `:${file}`], { cwd: root, maxBuffer: 8 * 1024 * 1024 });
const json = file => JSON.parse(blob(file));
for (const file of files) {
  if (forbidden.test(file) || (file.startsWith('reports/') && !allowedReports.has(file))) errors.push({ file, issue: 'private/local path in public index' });
  if (/(?:^|\/)(?:\.env(?:\..*)?|hosts\.yml|credentials(?:\..*)?|id_rsa|id_ed25519)$/.test(file)) errors.push({ file, issue: 'credential/config filename' });
  const data = blob(file), text = data.toString('utf8'); bytes += data.length;
  if (data.length > 1024 * 1024) errors.push({ file, issue: 'unexpected large public file' });
  if (data.includes(0)) errors.push({ file, issue: 'unexpected binary payload' });
  if (/C:[/\\]Users[/\\]user[/\\]|\/Users\/user\//i.test(text)) errors.push({ file, issue: 'operator-specific absolute path' });
  if (/github_pat_[A-Za-z0-9_]{35,}|gh[pousr]_[A-Za-z0-9]{30,}|-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----/.test(text)) errors.push({ file, issue: 'possible credential material' });
  if (file.endsWith('.md')) {
    const withoutCode = text.replace(/```[^\n]*\n[\s\S]*?```/g, '');
    for (const match of withoutCode.matchAll(/\]\(([^\s)]+)(?:\s+"[^"]*")?\)/g)) {
      const target = match[1].replace(/^<|>$/g, '');
      if (/^(?:https?:|mailto:|#)/.test(target)) continue;
      const relative = decodeURIComponent(target.split('#')[0]);
      const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(file), relative));
      if (!fileSet.has(resolved)) errors.push({ file, issue: 'relative Markdown link missing from public index', target });
    }
  }
}
const pkg = json('package.json');
for (const file of ['package-lock.json', 'npm-shrinkwrap.json', '.codex-plugin/plugin.json', '.claude-plugin/plugin.json']) {
  if (json(file).version !== pkg.version) errors.push({ file, issue: 'release version mismatch' });
}
if (!blob('src/contracts.ts').toString().includes(`export const VERSION = '${pkg.version}';`)) errors.push({ file: 'src/contracts.ts', issue: 'runtime version mismatch' });
const inventory = json('docs/shield-inventory.json');
if (inventory.files.length !== 51 || new Set(inventory.files.map(f => f.path)).size !== 51) errors.push({ file: 'docs/shield-inventory.json', issue: 'inventory completeness' });
const svg = blob('assets/readme-hero.svg').toString();
if (/<(?:script|foreignObject|iframe)\b|(?:href|src)\s*=\s*["'](?:https?:|javascript:)/i.test(svg)) errors.push({ file: 'assets/readme-hero.svg', issue: 'active or external SVG content' });
const summary = json('reports/v0.1-summary.json');
if (summary.version !== pkg.version || summary.measurements.fresh_agents.incremental_agent_win !== false || summary.measurements.genuine_flutter.exact_typed_labels !== 2) errors.push({ file: 'reports/v0.1-summary.json', issue: 'scope/version mismatch' });
console.log(JSON.stringify({ status: errors.length ? 'FAIL' : 'PUBLIC_INDEX_VERIFIED', version: pkg.version, files: files.length, bytes, errors }, null, 2));
process.exitCode = errors.length ? 1 : 0;

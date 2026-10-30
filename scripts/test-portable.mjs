import { existsSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

// These tests validate retained qualification evidence or invoke the pinned REA
// provider. They are deliberately separate from the clean-source product suite.
const researchTests = [
  'container-predicates.test.mjs', // 17 tests; executes the pinned REA source CLI.
  'container-audit-predicates.test.mjs', // 5 tests; rechecks private raw evidence.
];
const root = resolve(import.meta.dirname, '..');
const args = process.argv.slice(2);
if (args.length > 1 || (args.length === 1 && args[0] !== '--research')) {
  console.error('Usage: node scripts/test-portable.mjs [--research]');
  process.exit(2);
}

const research = args[0] === '--research';
let tests;
if (research) {
  const prerequisites = [
    '.runtime/node-v24.22.1-win-x64/node.exe',
    'research/rea/scripts/rea.mjs',
    'reports/C6-containers-2026-10-30T03-26-09-988Z.json',
  ];
  const missing = prerequisites.filter(file => !existsSync(join(root, file)));
  if (missing.length) {
    console.error('Research suite unavailable: 22 tests were not run. Missing local qualification prerequisites:');
    for (const file of missing) console.error(`  ${file}`);
    console.error('The retained report also requires its original source/command/stdout evidence paths. No research result is claimed.');
    process.exit(2);
  }
  tests = researchTests;
  console.error('Research suite: 22 tests against the pinned local REA provider and retained raw evidence.');
} else {
  tests = readdirSync(join(root, 'test'))
    .filter(file => file.endsWith('.test.mjs') && !researchTests.includes(file))
    .sort();
  console.error(`Portable suite: ${tests.length} test files; 22 research tests are excluded, not passed or skipped.`);
  console.error(`Research opt-in: node scripts/test-portable.mjs --research (${researchTests.join(', ')}).`);
}

if (!tests.length) {
  console.error('No test files were discovered.');
  process.exit(2);
}
const result = spawnSync(process.execPath, ['--test', ...tests.map(file => join('test', file))], {
  cwd: root,
  stdio: 'inherit',
  windowsHide: true,
});
if (result.error || result.signal || result.status === null) {
  console.error(`Test process did not complete: ${result.error?.message ?? result.signal ?? 'unknown exit'}`);
  process.exit(1);
}
process.exit(result.status);

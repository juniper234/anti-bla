import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readdir, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
const run = promisify(execFile);
const cli = path.resolve('dist/cli.js');

test('setup dry run produces concrete local MCP proposal without changing any files', async () => {
  const root = await mkdtemp(path.join(tmpdir(),'anti-bla-setup-'));
  const existing = path.join(root,'existing-config.json');
  await writeFile(existing,'{"keep":"untouched"}\n');
  const before = await readdir(root);
  const { stdout, stderr } = await run(process.execPath,[cli,'setup','--root',root,'--dry-run']);
  const r = JSON.parse(stdout);
  assert.equal(r.status,'ok');
  assert.equal(r.writes,false);
  assert.deepEqual(r.mcp.mcpServers['anti-bla'].args,[cli,'serve','--root',root]);
  assert.equal(r.mcp.mcpServers['anti-bla'].command,process.execPath);
  assert.ok(path.isAbsolute(r.skill.path));
  assert.deepEqual(await readdir(root),before);
  assert.equal(await readFile(existing,'utf8'),'{"keep":"untouched"}\n');
  assert.equal(stderr,'');
});

test('setup has no configuration-writing mode and requires one explicit existing artifact root', async () => {
  for (const args of [['setup','--root','.'],['setup','--dry-run'],['setup','--root','.','--root','src','--dry-run'],['setup','--root','.','--dry-run','--apply']]) {
    let rejected;
    try { await run(process.execPath,[cli,...args]); } catch(e) { rejected=e; }
    assert.ok(rejected);
    assert.equal(rejected.code,2);
    assert.equal(JSON.parse(rejected.stdout).status,'error');
  }
});

test('help can be discovered without opening an artifact or configuring roots', async () => {
  const {stdout} = await run(process.execPath,[cli,'--help']);
  const r=JSON.parse(stdout);
  assert.equal(r.status,'ok');
  assert.ok(r.commands.some(command=>command.name==='read-asar-entry'));
  assert.equal(r.targetExecution,false);
});

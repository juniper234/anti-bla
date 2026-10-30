#!/usr/bin/env node
import { AnalysisService } from './service.js';
import { serve } from './server.js';
import { failure, VERSION } from './contracts.js';
import { operations } from './contracts.js';
import { setupProposal } from './setup.js';
import type { Limits } from './contracts.js';

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  if (argv.length === 1 && argv[0] === '--version') { process.stdout.write(`${VERSION}\n`); return; }
  if (argv.length === 1 && ['--help', 'help'].includes(argv[0]!)) {
    process.stdout.write(`${JSON.stringify({ schema:'anti-bla.help/1',status:'ok',version:VERSION,targetExecution:false,
      commands:[...Object.keys(operations).filter(name=>name !== 'prepare_javascript_view').map(name=>({name:name.replaceAll('_','-')})),
        {name:'serve',usage:'serve --root <existing artifact directory>'},
        {name:'setup',usage:'setup --root <existing artifact directory> --dry-run'}],
      usage:'anti-bla <operation> [artifact path] --root <existing directory> [options]',
      options:['--workspace','--offset','--length','--limit','--member-path','--max-header-bytes','--max-entries','--entry-export','--export-name','--table','--tensor','--loader','--section','--assume-standard-intrinsics','--max-input-bytes','--max-output-bytes','--timeout-ms'],
      interpretation:'ok means the stated bounded task succeeded; behavioral equivalence and universal recovery remain unqualified.' })}\n`);
    return;
  }
  const operation = argv.shift()?.replaceAll('-', '_') ?? '';
  const roots: string[] = [];
  const limits: Partial<Limits> = {};
  const args: Record<string, string | number | boolean> = {};
  let dryRun = false;
  let workspace: string | undefined;
  while (argv.length) {
    const token = argv.shift()!;
    if (token === '--dry-run') { dryRun = true; }
    else if(token==='--assume-standard-intrinsics') {args.assumeStandardIntrinsics=true;}
    else if (token === '--workspace') {
      const value = argv.shift();
      if (!value || value.startsWith('--') || workspace !== undefined) throw new Error('workspace');
      workspace = value;
    }
    else if (token === '--root') {
      const value = argv.shift();
      if (!value || value.startsWith('--')) throw new Error('root');
      roots.push(value);
    } else if (['--member-path','--entry-export','--export-name','--table','--tensor','--loader','--section'].includes(token)) {
      const value = argv.shift();
      if (value === undefined) throw new Error('value');
      const field=token==='--member-path'?'memberPath':token==='--entry-export'?'entryExport':token==='--export-name'?'exportName':token.slice(2);
      args[field] = value;
    } else if (['--offset', '--length', '--limit', '--max-header-bytes', '--max-entries'].includes(token)) {
      const value = argv.shift();
      if (value === undefined) throw new Error('value');
      const field = token === '--max-header-bytes' ? 'maxHeaderBytes' : token === '--max-entries' ? 'maxEntries' : token.slice(2);
      args[field] = Number(value);
    } else if (['--max-input-bytes', '--max-output-bytes', '--timeout-ms'].includes(token)) {
      const value = argv.shift();
      if (value === undefined) throw new Error('value');
      const field = token === '--max-input-bytes' ? 'maxInputBytes' : token === '--max-output-bytes' ? 'maxOutputBytes' : 'timeoutMs';
      limits[field] = Number(value);
    } else if (!token.startsWith('--') && args.path === undefined) args.path = token;
    else throw new Error('invalid argument');
  }
  if (dryRun && operation !== 'setup') throw new Error('dry run scope');
  const service = await AnalysisService.create({ roots, limits, ...(workspace === undefined ? {} : { workspace }) });
  if (operation === 'setup') {
    if (!dryRun || roots.length !== 1 || Object.keys(args).length || Object.keys(limits).length) throw new Error('setup arguments');
    process.stdout.write(`${JSON.stringify(setupProposal(service.roots[0]!, service.workspace))}\n`);
    await service.close();
    return;
  }
  if (operation === 'serve') {
    if (Object.keys(args).length) throw new Error('serve arguments');
    await serve(service);
    return;
  }
  const result = await service.run(operation, args);
  process.stdout.write(`${JSON.stringify(result)}\n`);
  process.exitCode = result.status === 'ok' ? 0 : result.status === 'unknown' ? 3 : 2;
  await service.close();
}
main().catch(() => {
  const output = process.argv[2] === 'serve' ? process.stderr : process.stdout;
  output.write(`${JSON.stringify(failure('cli', 'invalid_request'))}\n`);
  process.exitCode = 2;
});

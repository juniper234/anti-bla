import { fileURLToPath } from 'node:url';

/** A concrete proposal only. There is intentionally no config-writing mode. */
export function setupProposal(root: string, workspace?: string) {
  return {
    schema: 'anti-bla.setup/1', status: 'ok', writes: false,
    mcp: { mcpServers: { 'anti-bla': {
      command: process.execPath,
      args: [fileURLToPath(new URL('./cli.js', import.meta.url)), 'serve', '--root', root, ...(workspace === undefined ? [] : ['--workspace', workspace])],
    } } },
    skill: { path: fileURLToPath(new URL('../skills/anti-bla/SKILL.md', import.meta.url)) },
    scope: { artifactRoot: root, targetExecution: false, network: false, analysisWrites: workspace !== undefined,
      ...(workspace === undefined ? {} : { workspace }) },
    next: 'Review this proposal and register it in your chosen local client configuration. This command wrote no configuration.',
  };
}

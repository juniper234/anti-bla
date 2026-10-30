import { fileURLToPath } from 'node:url';

// Local package entrypoint. The artifact root is supplied by the client or its
// trusted working directory; no target content controls launch configuration.
const cli = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
process.argv = [process.execPath, cli, 'serve', '--root', process.env.ANTI_BLA_ARTIFACT_ROOT ?? process.cwd()];
if (process.env.ANTI_BLA_WORKSPACE !== undefined) process.argv.push('--workspace', process.env.ANTI_BLA_WORKSPACE);
await import('../dist/cli.js');

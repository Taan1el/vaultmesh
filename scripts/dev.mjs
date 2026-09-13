// Starts the API and the Vite dev server together and stops both when either exits.
// Arguments after "--" go to Vite, for example: npm run dev -- --port 5174
import { spawn, spawnSync } from 'node:child_process';

const isWindows = process.platform === 'win32';
const viteArgs = process.argv.slice(2);

function start(args) {
  if (!isWindows) return spawn('npm', args, { stdio: 'inherit' });
  // npm is a .cmd file on Windows, which needs a shell. The shell gets one command string.
  const command = ['npm', ...args].map((arg) => (/[\s"]/.test(arg) ? `"${arg.replace(/"/g, '\\"')}"` : arg)).join(' ');
  return spawn(command, { stdio: 'inherit', shell: true });
}

const children = [
  start(['run', 'dev', '--workspace=server']),
  start(['run', 'dev', '--workspace=client', '--', ...viteArgs]),
];

let stopping = false;

function stopAll(exitCode) {
  if (stopping) return;
  stopping = true;
  for (const child of children) {
    if (child.exitCode !== null || child.pid === undefined) continue;
    if (isWindows) {
      // Kill the whole tree: the shell, npm and the node process it started.
      spawnSync('taskkill', ['/pid', String(child.pid), '/T', '/F'], { stdio: 'ignore' });
    } else {
      child.kill('SIGTERM');
    }
  }
  process.exit(exitCode);
}

for (const child of children) {
  child.on('exit', (code) => stopAll(code ?? 0));
}
process.on('SIGINT', () => stopAll(0));
process.on('SIGTERM', () => stopAll(0));

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// The compiled server lives in server/dist/server/src while the sources live in
// server/src, so paths are resolved from the server package root instead of
// from this file's directory.
function findServerRoot(startDir: string): string {
  let dir = startDir;
  for (;;) {
    const manifest = path.join(dir, 'package.json');
    if (fs.existsSync(manifest)) {
      try {
        const { name } = JSON.parse(fs.readFileSync(manifest, 'utf8')) as { name?: string };
        if (name === '@vaultmesh/server') return dir;
      } catch {
        // Unreadable manifest: keep walking up.
      }
    }
    const parent = path.dirname(dir);
    if (parent === dir) return process.cwd();
    dir = parent;
  }
}

export const serverRoot = findServerRoot(path.dirname(fileURLToPath(import.meta.url)));
export const repoRoot = path.resolve(serverRoot, '..');
export const defaultDbPath = path.join(serverRoot, 'data', 'vaultmesh.db');
export const defaultClientDir = path.join(repoRoot, 'client', 'dist');

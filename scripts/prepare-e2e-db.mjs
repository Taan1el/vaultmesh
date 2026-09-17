import fs from 'node:fs/promises';
import path from 'node:path';

const dbPath = path.resolve('.tmp', 'e2e', 'vaultmesh.db');

await fs.mkdir(path.dirname(dbPath), { recursive: true });

await Promise.all(
  ['', '-shm', '-wal'].map(async (suffix) => {
    await fs.rm(`${dbPath}${suffix}`, { force: true });
  })
);

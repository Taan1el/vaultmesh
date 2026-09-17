import { defineConfig, devices } from '@playwright/test';
import path from 'node:path';

const e2eDbPath = path.resolve('.tmp', 'e2e', 'vaultmesh.db');

export default defineConfig({
  testDir: './tests/e2e',
  timeout: 30_000,
  expect: {
    timeout: 10_000,
  },
  fullyParallel: false,
  use: {
    baseURL: 'http://127.0.0.1:3005',
    trace: 'on-first-retry',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: [
    {
      command: 'node scripts/prepare-e2e-db.mjs && npm run dev --workspace=server',
      url: 'http://127.0.0.1:4005/health',
      timeout: 30_000,
      reuseExistingServer: false,
      env: {
        PORT: '4005',
        VAULTMESH_DB_PATH: e2eDbPath,
      },
    },
    {
      command: 'npm run dev --workspace=client -- --host 127.0.0.1',
      url: 'http://127.0.0.1:3005',
      timeout: 30_000,
      reuseExistingServer: false,
    },
  ],
});

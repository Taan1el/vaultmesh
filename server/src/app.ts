import express from 'express';
import cors from 'cors';
import fs from 'node:fs';
import path from 'node:path';
import { VaultDatabase } from './db/database.js';
import { VaultService } from './services/vault.service.js';
import { VaultController } from './controllers/vault.controller.js';
import { createVaultRouter } from './routes/api.routes.js';
import { defaultClientDir } from './config.js';

export function createApp(dbPath?: string, clientDir: string = defaultClientDir) {
  const app = express();
  const db = new VaultDatabase(dbPath);
  const service = new VaultService(db);
  const controller = new VaultController(service);

  app.use(cors());
  app.use(express.json());

  app.get('/health', (_req, res) => {
    res.json({ status: 'ok', service: 'vaultmesh' });
  });

  app.use('/api', createVaultRouter(controller));

  // Serve the built dashboard when it exists (production and Docker).
  if (fs.existsSync(path.join(clientDir, 'index.html'))) {
    app.use(express.static(clientDir));
  }

  return { app, db, service, controller };
}

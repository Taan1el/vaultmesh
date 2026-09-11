import express from 'express';
import cors from 'cors';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { VaultDatabase } from './db/database.js';
import { VaultService } from './services/vault.service.js';
import { VaultController } from './controllers/vault.controller.js';
import { createVaultRouter } from './routes/api.routes.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export function createApp(dbPath?: string) {
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

  const clientDist = path.resolve(__dirname, '../../client/dist');
  app.use(express.static(clientDist));

  return { app, db, service, controller };
}
import express, { NextFunction, Request, Response } from 'express';
import cors from 'cors';
import fs from 'node:fs';
import path from 'node:path';
import { VaultDatabase } from './db/database.js';
import { VaultService } from './services/vault.service.js';
import { VaultController } from './controllers/vault.controller.js';
import { createVaultRouter } from './routes/api.routes.js';
import { defaultClientDir } from './config.js';
import { isVaultError } from '../../shared/errors.js';

interface HttpError {
  type?: string;
  status?: number;
}

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
  app.use('/api', (_req, res) => {
    res.status(404).json({ error: 'Not found' });
  });

  // Serve the built dashboard when it exists (production and Docker).
  if (fs.existsSync(path.join(clientDir, 'index.html'))) {
    app.use(express.static(clientDir));
  }

  app.use((err: unknown, _req: Request, res: Response, next: NextFunction) => {
    if (res.headersSent) {
      next(err);
      return;
    }
    if (isVaultError(err)) {
      res.status(err.status).json({ error: err.message });
      return;
    }
    const httpError = err as HttpError;
    if (httpError?.type === 'entity.parse.failed') {
      res.status(400).json({ error: 'Request body must be valid JSON' });
      return;
    }
    if (httpError?.type === 'entity.too.large') {
      res.status(413).json({ error: 'Request body is too large' });
      return;
    }
    if (typeof httpError?.status === 'number' && httpError.status >= 400 && httpError.status < 500) {
      res.status(httpError.status).json({ error: 'Invalid request' });
      return;
    }
    // Log only the stack: error objects from the body parser can carry the raw request body.
    console.error('Unhandled error:', err instanceof Error ? err.stack : 'non-error value thrown');
    res.status(500).json({ error: 'Internal server error' });
  });

  return { app, db, service, controller };
}

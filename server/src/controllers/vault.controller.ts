import { Request, Response } from 'express';
import { VaultService } from '../services/vault.service.js';

export class VaultController {
  constructor(private vaultService: VaultService) {}

  getStatus = (_req: Request, res: Response): void => {
    const state = this.vaultService.getState();
    res.json(state);
  };

  getDemoShares = (_req: Request, res: Response): void => {
    const shares = this.vaultService.getDemoShares();
    res.json({ shares });
  };

  seal = (req: Request, res: Response): void => {
    const actor = (req.headers['x-actor'] as string) || 'security-operator';
    const ip = req.ip || '127.0.0.1';
    const state = this.vaultService.seal(actor, ip);
    res.json({ message: 'Vault successfully sealed', state });
  };

  unseal = (req: Request, res: Response): void => {
    const { share } = req.body;
    if (!share || typeof share !== 'string') {
      res.status(400).json({ error: 'Share string is required' });
      return;
    }

    try {
      const actor = (req.headers['x-actor'] as string) || 'custodian';
      const ip = req.ip || '127.0.0.1';
      const progress = this.vaultService.submitUnsealShare(share, actor, ip);
      res.json(progress);
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  };

  resetUnseal = (_req: Request, res: Response): void => {
    this.vaultService.resetUnseal();
    res.json({ message: 'Unseal attempts reset' });
  };

  listKeks = (_req: Request, res: Response): void => {
    const versions = this.vaultService.listKekVersions();
    res.json(versions);
  };

  rotateKek = (req: Request, res: Response): void => {
    try {
      const actor = (req.headers['x-actor'] as string) || 'security-admin';
      const ip = req.ip || '127.0.0.1';
      const result = this.vaultService.rotateKek(actor, ip);
      res.json(result);
    } catch (err: any) {
      res.status(err.message.includes('sealed') ? 503 : 500).json({ error: err.message });
    }
  };

  rewrapSecrets = (req: Request, res: Response): void => {
    try {
      const actor = (req.headers['x-actor'] as string) || 'security-admin';
      const ip = req.ip || '127.0.0.1';
      const result = this.vaultService.rewrapSecrets(actor, ip);
      res.json(result);
    } catch (err: any) {
      res.status(err.message.includes('sealed') ? 503 : 500).json({ error: err.message });
    }
  };

  listSecrets = (_req: Request, res: Response): void => {
    const secrets = this.vaultService.listSecrets();
    res.json(secrets);
  };

  createSecret = (req: Request, res: Response): void => {
    const { path, name, description, plaintext, isDynamic, ttlSeconds, maxTtlSeconds } = req.body;
    if (!path || !name || plaintext === undefined) {
      res.status(400).json({ error: 'path, name, and plaintext are required fields' });
      return;
    }

    try {
      const actor = (req.headers['x-actor'] as string) || 'developer';
      const ip = req.ip || '127.0.0.1';
      const secret = this.vaultService.createSecret({
        path,
        name,
        description,
        plaintext: typeof plaintext === 'string' ? plaintext : JSON.stringify(plaintext),
        isDynamic,
        ttlSeconds,
        maxTtlSeconds,
      }, actor, ip);
      res.status(201).json(secret);
    } catch (err: any) {
      const status = err.message.includes('sealed') ? 503 : err.message.includes('already exists') ? 409 : 500;
      res.status(status).json({ error: err.message });
    }
  };

  readSecret = (req: Request, res: Response): void => {
    const rawPath = this.getWildcardPath(req);
    if (!rawPath) {
      res.status(400).json({ error: 'Path parameter is required' });
      return;
    }

    try {
      const actor = (req.headers['x-actor'] as string) || 'developer';
      const ip = req.ip || '127.0.0.1';
      const secret = this.vaultService.readSecret(rawPath, actor, ip);
      res.json(secret);
    } catch (err: any) {
      const status = err.message.includes('sealed') ? 503 : err.message.includes('not found') ? 404 : 500;
      res.status(status).json({ error: err.message });
    }
  };

  deleteSecret = (req: Request, res: Response): void => {
    const rawPath = this.getWildcardPath(req);
    if (!rawPath) {
      res.status(400).json({ error: 'Path parameter is required' });
      return;
    }

    try {
      const actor = (req.headers['x-actor'] as string) || 'developer';
      const ip = req.ip || '127.0.0.1';
      const deleted = this.vaultService.deleteSecret(rawPath, actor, ip);
      if (!deleted) {
        res.status(404).json({ error: `Secret at "${rawPath}" not found` });
        return;
      }
      res.json({ message: 'Secret deleted successfully', path: rawPath });
    } catch (err: any) {
      const status = err.message.includes('sealed') ? 503 : 500;
      res.status(status).json({ error: err.message });
    }
  };

  listLeases = (_req: Request, res: Response): void => {
    const leases = this.vaultService.listLeases();
    res.json(leases);
  };

  renewLease = (req: Request, res: Response): void => {
    const id = this.getParam(req.params.id);
    const { incrementSeconds } = req.body;
    try {
      const actor = (req.headers['x-actor'] as string) || 'client-app';
      const ip = req.ip || '127.0.0.1';
      const lease = this.vaultService.renewLease(id, incrementSeconds, actor, ip);
      res.json(lease);
    } catch (err: any) {
      const status = err.message.includes('sealed') ? 503 : 400;
      res.status(status).json({ error: err.message });
    }
  };

  revokeLease = (req: Request, res: Response): void => {
    const id = this.getParam(req.params.id);
    try {
      const actor = (req.headers['x-actor'] as string) || 'client-app';
      const ip = req.ip || '127.0.0.1';
      const lease = this.vaultService.revokeLease(id, actor, ip);
      res.json(lease);
    } catch (err: any) {
      const status = err.message.includes('sealed') ? 503 : 400;
      res.status(status).json({ error: err.message });
    }
  };

  getAuditLog = (req: Request, res: Response): void => {
    const limit = req.query.limit ? parseInt(req.query.limit as string, 10) : 50;
    const entries = this.vaultService.getAuditLog(limit);
    res.json(entries);
  };

  verifyAudit = (_req: Request, res: Response): void => {
    const result = this.vaultService.verifyAuditLedger();
    res.json(result);
  };

  private getWildcardPath(req: Request): string {
    const param = req.params[0] || (req.params as { path?: string | string[] }).path;
    return Array.isArray(param) ? param.join('/') : param || '';
  }

  private getParam(param: string | string[] | undefined): string {
    return Array.isArray(param) ? param[0] || '' : param || '';
  }
}

import { Request, Response } from 'express';
import { VaultService } from '../services/vault.service.js';
import { badRequest } from '../../../shared/errors.js';
import { parseAuditLimit, parseReadSecretOptions, sanitizeActor } from '../../../shared/validation.js';
import type { CreateSecretDto } from '../../../shared/types.js';

// Handlers are synchronous, so Express passes any thrown error to the JSON
// error handler registered in app.ts.
export class VaultController {
  constructor(private vaultService: VaultService) {}

  getStatus = (_req: Request, res: Response): void => {
    res.json(this.vaultService.getState());
  };

  getDemoShares = (_req: Request, res: Response): void => {
    res.json({ shares: this.vaultService.getDemoShares() });
  };

  seal = (req: Request, res: Response): void => {
    const state = this.vaultService.seal(this.actor(req, 'security-operator'), this.ip(req));
    res.json({ message: 'Vault sealed', state });
  };

  unseal = (req: Request, res: Response): void => {
    const { share } = req.body ?? {};
    if (!share || typeof share !== 'string') {
      throw badRequest('share is required and must be a string');
    }
    res.json(this.vaultService.submitUnsealShare(share, this.actor(req, 'custodian'), this.ip(req)));
  };

  resetUnseal = (_req: Request, res: Response): void => {
    this.vaultService.resetUnseal();
    res.json({ message: 'Unseal attempts reset' });
  };

  listKeks = (_req: Request, res: Response): void => {
    res.json(this.vaultService.listKekVersions());
  };

  rotateKek = (req: Request, res: Response): void => {
    res.json(this.vaultService.rotateKek(this.actor(req, 'security-admin'), this.ip(req)));
  };

  rewrapSecrets = (req: Request, res: Response): void => {
    res.json(this.vaultService.rewrapSecrets(this.actor(req, 'security-admin'), this.ip(req)));
  };

  listSecrets = (_req: Request, res: Response): void => {
    res.json(this.vaultService.listSecrets());
  };

  createSecret = (req: Request, res: Response): void => {
    // The service validates the body and applies defaults.
    const body = req.body as CreateSecretDto;
    const secret = this.vaultService.createSecret(body, this.actor(req, 'developer'), this.ip(req));
    res.status(201).json(secret);
  };

  readSecret = (req: Request, res: Response): void => {
    const rawPath = this.getWildcardPath(req);
    if (!rawPath) throw badRequest('Path parameter is required');
    res.json(this.vaultService.readSecret(rawPath, this.actor(req, 'developer'), this.ip(req), parseReadSecretOptions(req.query)));
  };

  deleteSecret = (req: Request, res: Response): void => {
    const rawPath = this.getWildcardPath(req);
    if (!rawPath) throw badRequest('Path parameter is required');
    const deleted = this.vaultService.deleteSecret(rawPath, this.actor(req, 'developer'), this.ip(req));
    res.json({ message: 'Secret deleted', path: deleted.path });
  };

  listLeases = (_req: Request, res: Response): void => {
    res.json(this.vaultService.listLeases());
  };

  renewLease = (req: Request, res: Response): void => {
    const id = this.getParam(req.params.id);
    const { incrementSeconds } = req.body ?? {};
    res.json(this.vaultService.renewLease(id, incrementSeconds, this.actor(req, 'client-app'), this.ip(req)));
  };

  revokeLease = (req: Request, res: Response): void => {
    const id = this.getParam(req.params.id);
    res.json(this.vaultService.revokeLease(id, this.actor(req, 'client-app'), this.ip(req)));
  };

  getAuditLog = (req: Request, res: Response): void => {
    const limit = parseAuditLimit(req.query.limit);
    res.json(this.vaultService.getAuditLog(limit));
  };

  verifyAudit = (_req: Request, res: Response): void => {
    res.json(this.vaultService.verifyAuditLedger());
  };

  private actor(req: Request, fallback: string): string {
    return sanitizeActor(req.headers['x-actor'], fallback);
  }

  private ip(req: Request): string {
    return req.ip || '127.0.0.1';
  }

  private getWildcardPath(req: Request): string {
    const param = req.params[0] || (req.params as { path?: string | string[] }).path;
    return Array.isArray(param) ? param.join('/') : param || '';
  }

  private getParam(param: string | string[] | undefined): string {
    return Array.isArray(param) ? param[0] || '' : param || '';
  }
}

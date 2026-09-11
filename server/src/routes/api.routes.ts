import { Router } from 'express';
import { VaultController } from '../controllers/vault.controller.js';

export function createVaultRouter(controller: VaultController): Router {
  const router = Router();

  // Vault Core & Seal Management
  router.get('/vault/status', controller.getStatus);
  router.get('/vault/demo-shares', controller.getDemoShares);
  router.post('/vault/seal', controller.seal);
  router.post('/vault/unseal', controller.unseal);
  router.post('/vault/unseal/reset', controller.resetUnseal);

  // KEK Versioning & Key Rotation
  router.get('/vault/keks', controller.listKeks);
  router.post('/vault/keks/rotate', controller.rotateKek);
  router.post('/vault/keks/rewrap', controller.rewrapSecrets);

  // Secrets Management
  router.get('/secrets', controller.listSecrets);
  router.post('/secrets', controller.createSecret);
  router.get('/secrets/*', controller.readSecret);
  router.delete('/secrets/*', controller.deleteSecret);

  // Dynamic Leases
  router.get('/leases', controller.listLeases);
  router.post('/leases/:id/renew', controller.renewLease);
  router.post('/leases/:id/revoke', controller.revokeLease);

  // Cryptographic Audit Ledger
  router.get('/audit', controller.getAuditLog);
  router.get('/audit/verify', controller.verifyAudit);

  return router;
}
// Errors that are safe to show to API callers. Anything else is reported as a
// generic 500 so internal details (SQL, crypto library messages) never leak.
export class VaultError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = 'VaultError';
    this.status = status;
  }
}

export const badRequest = (message: string) => new VaultError(400, message);
export const forbidden = (message: string) => new VaultError(403, message);
export const notFound = (message: string) => new VaultError(404, message);
export const conflict = (message: string) => new VaultError(409, message);
export const vaultSealed = () =>
  new VaultError(503, 'Vault is sealed. Submit custodian shares to unseal it first.');

export function isVaultError(error: unknown): error is VaultError {
  return error instanceof VaultError;
}

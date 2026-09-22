import type { ReadSecretOptions, SecretAccessDecision } from './types.js';

export const READ_APPROVAL_CODE = 'VM-APPROVED';
export const DEFAULT_READ_PURPOSE = 'Direct operator read';

const SENSITIVE_PREFIXES = ['secret/production/', 'secret/payments/', 'secret/cloud/'];

export function isSensitiveSecretPath(path: string): boolean {
  return SENSITIVE_PREFIXES.some((prefix) => path.startsWith(prefix));
}

export function evaluateReadPolicy(path: string, options: ReadSecretOptions = {}): SecretAccessDecision {
  const purpose = options.purpose?.trim() || DEFAULT_READ_PURPOSE;
  const requiresApproval = isSensitiveSecretPath(path) && Boolean(options.purpose?.trim());

  if (requiresApproval && options.approvalCode?.trim() !== READ_APPROVAL_CODE) {
    return {
      status: 'APPROVAL_REQUIRED',
      reason: `Sensitive path reads need approval code ${READ_APPROVAL_CODE}`,
      purpose,
      approvalCodeRequired: true,
    };
  }

  return {
    status: 'ALLOWED',
    reason: requiresApproval ? 'Approval code accepted for sensitive path' : 'No approval gate matched this path',
    purpose,
    approvalCodeRequired: requiresApproval,
  };
}

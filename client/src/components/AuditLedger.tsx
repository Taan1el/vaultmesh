import type { AuditEntry, AuditVerificationResult } from '../../../shared/types';
import { formatTime, maskHex } from './format';

interface AuditLedgerProps {
  entries: AuditEntry[];
  verification: AuditVerificationResult | null;
}

function verificationLabel(verification: AuditVerificationResult | null): string {
  if (!verification) return 'Not checked yet';
  if (verification.isValid) return `Chain verified, ${verification.totalEntries} entries`;
  return `Chain broken at entry ${(verification.brokenIndex ?? 0) + 1}`;
}

export function AuditLedger({ entries, verification }: AuditLedgerProps) {
  const broken = verification ? !verification.isValid : false;

  return (
    <section className="panel" aria-labelledby="audit-title">
      <div className="panel-heading">
        <h2 id="audit-title">Audit ledger</h2>
        <span className={broken ? 'danger-text' : undefined}>{verificationLabel(verification)}</span>
      </div>
      <p className="muted">Latest {entries.length} entries. Each hash covers the entry and the hash before it.</p>
      <ul className="stack-list">
        {entries.map((entry) => (
          <li key={entry.id} className="list-item">
            <div>
              <strong>
                {entry.action}
                {entry.status !== 'SUCCESS' ? <span className="tag warn">{entry.status}</span> : null}
              </strong>
              <small>{entry.details}</small>
              <small>
                {entry.actor} at {formatTime(entry.timestamp)}
              </small>
            </div>
            <span className="mono hash" title={entry.entryHash}>
              {maskHex(entry.entryHash)}
            </span>
          </li>
        ))}
      </ul>
    </section>
  );
}

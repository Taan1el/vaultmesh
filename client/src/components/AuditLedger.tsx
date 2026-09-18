import type { AuditEntry, AuditVerificationResult } from '../../../shared/types';
import { countLabel, formatTime, maskHex } from './format';

interface AuditLedgerProps {
  entries: AuditEntry[];
  verification: AuditVerificationResult | null;
}

function verificationLabel(verification: AuditVerificationResult | null): string {
  if (!verification) return 'Not checked yet';
  if (verification.isValid) return `Chain verified, ${countLabel(verification.totalEntries, 'entry', 'entries')}`;
  return `Chain broken at entry ${(verification.brokenIndex ?? 0) + 1}`;
}

export function AuditLedger({ entries, verification }: AuditLedgerProps) {
  const broken = verification ? !verification.isValid : false;

  return (
    <section className="panel" aria-labelledby="audit-title">
      <div className="panel-heading">
        <h2 id="audit-title">Audit ledger</h2>
        <span className={broken ? 'danger-text' : 'muted'}>{verificationLabel(verification)}</span>
      </div>
      <p className="muted" style={{ marginBottom: '0.75rem' }}>
        Latest {countLabel(entries.length, 'entry', 'entries')}. Each hash covers the entry and the hash before it.
      </p>
      <ul className="dense-list">
        {entries.map((entry) => (
          <li key={entry.id} className="dense-row">
            <div className="dense-row-main">
              <strong>
                {entry.action}
                {entry.status !== 'SUCCESS' ? <span className="tag warn"> {entry.status}</span> : null}
              </strong>
              <small>
                {entry.details} &middot; {entry.actor} at {formatTime(entry.timestamp)}
              </small>
            </div>
            <span className="dense-row-value" title={entry.entryHash}>
              {maskHex(entry.entryHash)}
            </span>
          </li>
        ))}
      </ul>
    </section>
  );
}

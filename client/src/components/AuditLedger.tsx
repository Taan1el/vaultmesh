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
        <h3 id="audit-title">Audit ledger</h3>
        <span className={broken ? 'danger-text' : 'muted'}>{verificationLabel(verification)}</span>
      </div>
      <p className="panel-note">
        Latest {countLabel(entries.length, 'entry', 'entries')}. Each hash covers the entry and the hash before it.
      </p>
      <div className="table-wrap" role="region" tabIndex={0} aria-label="Audit ledger table">
        <table>
          <thead>
            <tr>
              <th scope="col">Action</th>
              <th scope="col">Detail</th>
              <th scope="col">Actor</th>
              <th scope="col">Time</th>
              <th scope="col">Hash</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((entry) => (
              <tr key={entry.id}>
                <td>
                  <strong>
                    {entry.action}
                    {entry.status !== 'SUCCESS' ? <span className="tag warn">{entry.status}</span> : null}
                  </strong>
                </td>
                <td>{entry.details}</td>
                <td className="mono">{entry.actor}</td>
                <td className="mono">{formatTime(entry.timestamp)}</td>
                <td className="mono" title={entry.entryHash}>
                  {maskHex(entry.entryHash)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

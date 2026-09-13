import { useState } from 'react';
import type { VaultState } from '../../../shared/types';
import { shareIndex } from './format';

interface UnsealPanelProps {
  state: VaultState | null;
  shares: string[];
  busy: boolean;
  onSubmit: (share: string) => Promise<boolean>;
  onReset: () => void;
}

export function UnsealPanel({ state, shares, busy, onSubmit, onReset }: UnsealPanelProps) {
  const [shareInput, setShareInput] = useState('');
  const sealed = state?.status === 'SEALED';
  const threshold = state?.threshold ?? 3;
  const submitted = state?.submittedShareIndexes ?? [];
  const nextSample = shares.find((share) => {
    const index = shareIndex(share);
    return index !== null && !submitted.includes(index);
  });

  async function submit() {
    if (await onSubmit(shareInput)) {
      setShareInput('');
    }
  }

  return (
    <section className="panel" aria-labelledby="unseal-title">
      <div className="panel-heading">
        <h2 id="unseal-title">Custodian unseal</h2>
        <span>{sealed ? `${state?.sharesSubmitted ?? 0} of ${threshold} shares` : 'Unsealed'}</span>
      </div>
      {sealed ? (
        <>
          <p className="muted">
            Submit any {threshold} of the {state?.totalShares ?? 5} custodian shares to rebuild the root key.
            {submitted.length > 0 ? ` Received so far: share ${submitted.join(', share ')}.` : ''}
          </p>
          <label htmlFor="custodian-share">Custodian share</label>
          <textarea
            id="custodian-share"
            value={shareInput}
            onChange={(event) => setShareInput(event.target.value)}
            rows={3}
            spellCheck={false}
            autoComplete="off"
            placeholder="vmshare-01-..."
          />
          <div className="button-row">
            <button type="button" onClick={() => void submit()} disabled={busy || !shareInput.trim()}>
              Submit share
            </button>
            <button
              type="button"
              className="secondary"
              onClick={() => setShareInput(nextSample ?? '')}
              disabled={!nextSample}
            >
              Load next sample share
            </button>
            {submitted.length > 0 ? (
              <button type="button" className="secondary" onClick={onReset} disabled={busy}>
                Clear submitted shares
              </button>
            ) : null}
          </div>
          <p className="hint">
            This local build exposes all sample shares so you can try the flow. Real custodians would each hold one
            share offline.
          </p>
        </>
      ) : (
        <p className="muted">
          The vault is unsealed. Seal it to clear the root key from memory, then unseal it here with {threshold} shares.
        </p>
      )}
    </section>
  );
}

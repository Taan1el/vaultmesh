import { useEffect, useRef } from 'react';
import type { DecryptedSecret } from '../../../shared/types';
import { formatDateTime } from './format';

interface SecretDrawerProps {
  secret: DecryptedSecret;
  onClose: () => void;
}

export function SecretDrawer({ secret, onClose }: SecretDrawerProps) {
  const closeRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    closeRef.current?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [onClose]);

  const body = secret.parsedData ? JSON.stringify(secret.parsedData, null, 2) : secret.plaintext;

  return (
    <section className="drawer" role="dialog" aria-modal="false" aria-labelledby="drawer-title">
      <div>
        <p className="eyebrow">Decrypted value</p>
        <h2 id="drawer-title">{secret.name}</h2>
        <p className="muted">
          {secret.path}, encrypted under KEK v{secret.kekVersion}
        </p>
      </div>
      <pre>{body}</pre>
      {secret.lease ? (
        <p className="muted">
          Lease {secret.lease.id} expires {formatDateTime(secret.lease.expiresAt)}.
        </p>
      ) : null}
      <button ref={closeRef} type="button" className="secondary" onClick={onClose}>
        Close
      </button>
    </section>
  );
}

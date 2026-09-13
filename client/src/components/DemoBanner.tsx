interface DemoBannerProps {
  onReset: () => void;
  busy: boolean;
}

export function DemoBanner({ onReset, busy }: DemoBannerProps) {
  return (
    <aside className="demo-banner" aria-label="Demo mode">
      <p>
        Demo mode: data is simulated in your browser. Encryption uses the Web Crypto API and nothing is sent to a
        server. <a href="https://github.com/Taan1el/vaultmesh">Source on GitHub</a>
      </p>
      <button type="button" className="small secondary" onClick={onReset} disabled={busy}>
        Reset demo data
      </button>
    </aside>
  );
}

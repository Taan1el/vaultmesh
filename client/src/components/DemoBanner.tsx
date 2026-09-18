interface DemoBannerProps {
  onReset: () => void;
  busy: boolean;
}

export function DemoBanner({ onReset, busy }: DemoBannerProps) {
  return (
    <div className="demo-bar" role="complementary" aria-label="Demo mode">
      <div className="demo-bar-inner">
        <span>Demo: everything runs in your browser with sample data.</span>
        <span className="demo-bar-links">
          <button type="button" className="link-btn" onClick={onReset} disabled={busy}>
            Reset sample data
          </button>
          <a href="https://github.com/Taan1el/vaultmesh" target="_blank" rel="noreferrer">
            Source on GitHub
          </a>
        </span>
      </div>
    </div>
  );
}

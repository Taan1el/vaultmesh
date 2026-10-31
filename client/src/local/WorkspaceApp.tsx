import { useEffect, useState } from 'react';
import { App } from '../App';
import { isDemoMode } from '../services/api';
import { LocalVault } from './LocalVault';
import { loadMode, saveMode, type WorkspaceMode } from './workspace';
import './local.css';

export function WorkspaceApp() {
  const [mode, setMode] = useState<WorkspaceMode>('sample');
  const [error, setError] = useState('');
  const [ready, setReady] = useState(false);
  const [install, setInstall] = useState<(Event & { prompt(): Promise<void> }) | null>(null);
  useEffect(() => {
    if (!isDemoMode) return;
    let active = true;
    void loadMode().then((saved) => { if (active) setMode(saved); }).catch(() => setError('Browser storage is unavailable. Keep an encrypted export.')).finally(() => { if (active) setReady(true); });
    const offered = (event: Event) => { event.preventDefault(); setInstall(event as Event & { prompt(): Promise<void> }); };
    window.addEventListener('beforeinstallprompt', offered);
    return () => { active = false; window.removeEventListener('beforeinstallprompt', offered); };
  }, []);
  if (!isDemoMode) return <App />;
  return <div className="app-shell"><section className="local-source" aria-label="Browser data source"><div className="field"><label htmlFor="local-data-source">Data source</label><select id="local-data-source" value={mode} disabled={!ready} onChange={(event) => {
    const next = event.target.value as WorkspaceMode;
    if (mode === 'workspace' && !window.confirm('Leave your workspace and lock its decrypted contents? Saved encrypted data is kept.')) return;
    void saveMode(next).then(() => { setMode(next); setError(''); }).catch(() => setError('Data source could not be saved.'));
  }}><option value="sample">Sample data</option><option value="workspace">Your workspace</option></select></div><p>Your data stays in this browser. No requests to other hosts.</p>{install && <button className="btn" type="button" onClick={() => void install.prompt().then(() => setInstall(null))}>Install VaultMesh</button>}{error && <p role="alert">{error}</p>}</section>{ready && (mode === 'workspace' ? <LocalVault /> : <App />)}</div>;
}

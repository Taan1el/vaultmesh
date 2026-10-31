import { useCallback, useEffect, useRef, useState, type FormEvent, type RefObject } from 'react';
import { Copy, Download, LockKeyhole, Plus, Trash2, Upload, X } from 'lucide-react';
import { ClipboardGuard } from './clipboard';
import { downloadFile } from './files';
import { loadWorkspaceSnapshot, saveWorkspace, WorkspaceConflictError } from './workspace';
import { createVault, MAX_VAULT_BYTES, parseVault, putEntry, recoverVault, recoveryShares, rotatePassphrase, sealData, serializeVault, unlockVault, type Entry, type VaultFile, type VaultSession } from './vault';
import './local.css';

const sections = ['Status', 'Secrets', 'Keys', 'Leases', 'Audit'] as const;
type Section = typeof sections[number];
function message(error: unknown) { return error instanceof Error ? error.message : 'The operation could not finish.'; }

export function LocalVault() {
  const [file, setFile] = useState<VaultFile | null>(null);
  const [session, setSession] = useState<VaultSession | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [blocked, setBlocked] = useState(false);
  const [busy, setBusy] = useState(false);
  const [section, setSection] = useState<Section>('Status');
  const [error, setError] = useState('');
  const [status, setStatus] = useState('');
  const [pass, setPass] = useState('');
  const [nextPass, setNextPass] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [path, setPath] = useState('');
  const [value, setValue] = useState('');
  const [editing, setEditing] = useState<string | undefined>();
  const [revealed, setRevealed] = useState<string | null>(null);
  const [shares, setShares] = useState<string[]>([]);
  const [recovery, setRecovery] = useState('');
  const [recovering, setRecovering] = useState(false);
  const [dialog, setDialog] = useState(false);
  const [idleMinutes, setIdleMinutes] = useState(5);
  const [hideLock, setHideLock] = useState(true);
  const [changes, setChanges] = useState(false);
  const [backupSeen, setBackupSeen] = useState(() => { try { return sessionStorage.getItem('vaultmesh-backup') === 'seen'; } catch { return false; } });
  const [audit, setAudit] = useState<string[]>([]);
  const revision = useRef(0);
  const epoch = useRef(0);
  const liveSession = useRef<VaultSession | null>(null);
  const activity = useRef(Date.now());
  const clipboard = useRef<ClipboardGuard | null>(null);
  const opener = useRef<HTMLButtonElement>(null);
  const exportButton = useRef<HTMLButtonElement>(null);
  const isDisabled = !loaded || busy;

  const lock = useCallback(() => {
    epoch.current += 1;
    liveSession.current?.key.fill(0); liveSession.current = null;
    setSession(null); setPath(''); setValue(''); setEditing(undefined); setRevealed(null);
    setPass(''); setNextPass(''); setConfirmation(''); setShares([]); setRecovery(''); setRecovering(false); setAudit([]);
    void clipboard.current?.clear(); setStatus('Vault locked. Decrypted contents and recovery shares were cleared from this page.');
  }, []);

  useEffect(() => {
    let active = true;
    void loadWorkspaceSnapshot<VaultFile>().then((saved) => {
      const restored = saved.data === null ? null : parseVault(JSON.stringify(saved.data), 'Saved vault');
      if (active) { revision.current = saved.revision; setFile(restored); }
    }).catch((reason) => { if (active) { setBlocked(true); setError(`Saved vault could not be loaded. Writes are blocked to preserve it. ${message(reason)}`); } })
      .finally(() => { if (active) setLoaded(true); });
    return () => { active = false; epoch.current += 1; liveSession.current?.key.fill(0); liveSession.current = null; void clipboard.current?.clear(); };
  }, []);

  useEffect(() => {
    if (!session) return;
    activity.current = Date.now();
    const touch = () => { activity.current = Date.now(); };
    const hidden = () => { if (hideLock && document.visibilityState === 'hidden') lock(); };
    document.addEventListener('pointerdown', touch); document.addEventListener('keydown', touch); document.addEventListener('visibilitychange', hidden);
    const timer = window.setInterval(() => { if (Date.now() - activity.current >= idleMinutes * 60_000) lock(); }, 1000);
    return () => { clearInterval(timer); document.removeEventListener('pointerdown', touch); document.removeEventListener('keydown', touch); document.removeEventListener('visibilitychange', hidden); };
  }, [session, idleMinutes, hideLock, lock]);

  function adopt(next: VaultSession) {
    if (liveSession.current && liveSession.current.key !== next.key) liveSession.current.key.fill(0);
    liveSession.current = next; setSession(next); activity.current = Date.now();
  }
  async function run(action: (operation: number) => Promise<void>) {
    const operation = epoch.current; setBusy(true); setError(''); setStatus('');
    try { await action(operation); }
    catch (reason) { setError(message(reason)); }
    finally { setBusy(false); }
  }
  function current(operation: number) { if (epoch.current !== operation) throw new Error('The vault was locked before the operation finished. Unlock it again.'); }
  async function persist(next: VaultFile | null, operation: number) {
    current(operation);
    if (blocked) throw new Error('Reload saved vault before making changes.');
    try { revision.current = await saveWorkspace(next, { expectedRevision: revision.current }); }
    catch (reason) {
      if (reason instanceof WorkspaceConflictError) { lock(); setBlocked(true); }
      throw reason;
    }
    current(operation); setFile(next); setChanges(true);
  }
  function record(action: string) { setAudit((previous) => [`${new Date().toISOString()} ${action}`, ...previous].slice(0, 50)); }
  async function open(event: FormEvent) {
    event.preventDefault();
    if (!file && (pass !== confirmation)) { setError('Passphrase confirmation does not match.'); return; }
    await run(async (operation) => {
      let opened: VaultSession | undefined;
      try {
        if (file) {
          const saved = await loadWorkspaceSnapshot<VaultFile>();
          current(operation);
          if (saved.revision !== revision.current) { setBlocked(true); throw new WorkspaceConflictError(); }
          opened = await unlockVault(file, pass);
        } else {
          const created = await createVault(pass); opened = created.session;
          await persist(created.file, operation);
        }
        current(operation); adopt(opened); setSection('Secrets'); setPass(''); setConfirmation(''); setStatus('Vault unlocked.'); record('Vault unlocked');
      } catch (reason) { opened?.key.fill(0); throw reason; }
    });
  }
  async function saveEntry(event: FormEvent) {
    event.preventDefault(); if (!file || !session) return;
    await run(async (operation) => {
      const data = putEntry(session.data, path, value, editing);
      const next = await sealData(file, session.key, data);
      await persist(next, operation); adopt({ key: session.key, data }); setPath(''); setValue(''); setEditing(undefined); setStatus('Secret encrypted and saved.'); record('Secret saved');
    });
  }
  function removeEntry(entry: Entry) {
    if (!file || !session || !window.confirm(`Delete ${entry.path}? Export an encrypted backup first. This cannot be undone.`)) return;
    void run(async (operation) => {
      const data = { ...session.data, entries: session.data.entries.filter((item) => item.id !== entry.id) };
      await persist(await sealData(file, session.key, data), operation); adopt({ key: session.key, data }); setRevealed(null);
      setPath(''); setValue(''); setEditing(undefined); setStatus('Secret deleted.'); record('Secret deleted');
    });
  }
  async function copy(text: string) {
    if (!navigator.clipboard) throw new Error('Clipboard is unavailable. Select and copy the visible value manually.');
    clipboard.current ??= new ClipboardGuard(navigator.clipboard, () => setError('Clipboard could not be cleared. Clear it manually.'));
    await clipboard.current.copy(text); setStatus('Copied. Clipboard clearing is scheduled in 30 seconds.');
  }
  return <div className="frame local-vault">
    <aside className="rail"><div className="rail-brand"><h1 className="brand-name">VaultMesh</h1><p className="brand-subtitle">An encrypted notebook for secrets on this device.</p></div>
      <nav className="rail-nav" aria-label="Sections"><ul>{sections.map((item) => <li key={item}><button className="rail-link" type="button" aria-current={section === item ? 'page' : undefined} onClick={() => setSection(item)}><span>{item}</span><span className="rail-count">{item === 'Secrets' ? session?.data.entries.length ?? 'Locked' : item === 'Audit' ? audit.length : item === 'Keys' ? 1 : item === 'Leases' ? 0 : session ? 'Open' : 'Locked'}</span></button></li>)}</ul></nav>
      <div className="rail-foot">Local encrypted workspace<br />No account or server</div></aside>
    <main className="app-main">
      <header className="topbar"><div><h2 className="page-title">{section}</h2><p className="page-lede">Your data stays in this browser.</p><p className="hint">No requests to other hosts. This is an encrypted notebook for secrets, not an audited password manager.</p></div>
        <div className="topbar-actions"><button ref={opener} className="btn" type="button" disabled={isDisabled} onClick={() => setDialog(true)}><Upload size={16} aria-hidden="true" />Import vault</button>
          <button ref={exportButton} className="btn" type="button" disabled={!file || isDisabled} onClick={() => { if (!file) return; try { downloadFile('vaultmesh-encrypted.json', serializeVault(file), 'application/json'); setBackupSeen(true); try { sessionStorage.setItem('vaultmesh-backup', 'seen'); } catch { /* Backup remains usable without session storage. */ } setStatus('Encrypted vault exported. Keep the passphrase or recovery shares separately.'); } catch (reason) { setError(message(reason)); } }}><Download size={16} aria-hidden="true" />Export vault</button>
          <button className="btn btn-secondary" type="button" disabled={!session} onClick={lock}><LockKeyhole size={16} aria-hidden="true" />Lock vault</button></div>
      </header>
      {changes && !backupSeen && <p className="hint local-backup"><a href="#vault-backup" onClick={(event) => { event.preventDefault(); exportButton.current?.focus(); }}>Keep an encrypted backup outside this browser</a>. Browser data can be cleared.</p>}
      {error && <p role="alert" className="notice error">{error}</p>}
      <p role="status" className="local-status">{status || (!loaded ? 'Loading encrypted workspace.' : session ? 'Unlocked. Decrypted data is held in memory.' : 'Locked. Only ciphertext is stored.')}</p>
      {blocked && <button className="btn" type="button" disabled={busy} onClick={() => void run(async () => {
        lock(); const saved = await loadWorkspaceSnapshot<VaultFile>(); const parsed = saved.data === null ? null : parseVault(JSON.stringify(saved.data), 'Saved vault');
        revision.current = saved.revision; setFile(parsed); setBlocked(false); setStatus('Saved encrypted vault reloaded. Unlock it to continue.');
      })}>Reload saved vault</button>}
      <div className="section">
        {!session && <section className="panel" aria-labelledby="unlock-title"><div className="panel-heading"><h3 id="unlock-title">{file ? 'Unlock encrypted vault' : 'Create your encrypted vault'}</h3></div>
          <form onSubmit={(event) => void open(event)}><label>Passphrase<input type="password" autoComplete={file ? 'current-password' : 'new-password'} minLength={12} maxLength={1024} required value={pass} disabled={isDisabled || blocked} onChange={(event) => setPass(event.target.value)} /></label>
            {!file && <label>Confirm passphrase<input type="password" autoComplete="new-password" required minLength={12} value={confirmation} disabled={isDisabled || blocked} onChange={(event) => setConfirmation(event.target.value)} /></label>}
            <p className="hint">Use at least 12 characters. The passphrase is never saved. Keep an encrypted export and three recovery shares to recover without it.</p>
            <button className="btn btn-primary" disabled={isDisabled || blocked} type="submit">{busy ? 'Working' : file ? 'Unlock vault' : 'Create vault'}</button></form>
          {file && <><button type="button" className="link-btn" disabled={isDisabled || blocked} onClick={() => setRecovering(!recovering)}>Recover with shares</button>{recovering && <form onSubmit={(event) => { event.preventDefault(); void run(async (operation) => {
            if (nextPass !== confirmation) throw new Error('Passphrase confirmation does not match.');
            const restored = await recoverVault(file, recovery.split(/\r?\n/).map((line) => line.trim()).filter(Boolean), nextPass);
            try { await persist(restored.file, operation); adopt(restored.session); setPass(''); setRecovery(''); setNextPass(''); setConfirmation(''); setRecovering(false); setStatus('Vault recovered with a new passphrase. Export a fresh backup.'); } catch (reason) { restored.session.key.fill(0); throw reason; }
          }); }}><label>Recovery shares, one per line<textarea aria-label="Recovery shares, one per line" value={recovery} rows={5} autoComplete="off" spellCheck={false} onChange={(event) => setRecovery(event.target.value)} /></label><label>New recovery passphrase<input type="password" minLength={12} maxLength={1024} required autoComplete="new-password" value={nextPass} onChange={(event) => setNextPass(event.target.value)} /></label><label>Confirm recovery passphrase<input type="password" required autoComplete="new-password" value={confirmation} onChange={(event) => setConfirmation(event.target.value)} /></label><button className="btn btn-primary" type="submit" disabled={isDisabled || blocked}>Recover vault</button></form>}</>}
        </section>}
        {session && section === 'Secrets' && <>
          <section className="panel" aria-labelledby="secrets-title"><div className="panel-heading"><h3 id="secrets-title">Encrypted secret ledger</h3><span className="mono">{session.data.entries.length} {session.data.entries.length === 1 ? 'entry' : 'entries'}</span></div>
            {!session.data.entries.length ? <p>No secrets yet. Add a path and value below.</p> : <div className="table-scroll" role="region" tabIndex={0} aria-label="Encrypted secret inventory"><table><thead><tr><th scope="col">Index</th><th scope="col">Path</th><th scope="col">Key version</th><th scope="col">Updated</th><th scope="col">Actions</th></tr></thead><tbody>{session.data.entries.map((entry, index) => <tr key={entry.id}><td className="mono">{String(index + 1).padStart(2, '0')}</td><th scope="row" className="mono local-wrap">{entry.path}</th><td className="mono">1</td><td className="mono">{new Date(entry.updatedAt).toISOString().slice(0, 10)}</td><td><div className="button-row"><button className="btn" type="button" disabled={isDisabled} onClick={() => setRevealed(revealed === entry.id ? null : entry.id)}>{revealed === entry.id ? 'Hide' : 'Inspect'}<span className="sr-only"> {entry.path}</span></button><button className="btn" type="button" disabled={isDisabled || blocked} onClick={() => { setEditing(entry.id); setPath(entry.path); setValue(entry.value); setRevealed(null); }}>Edit<span className="sr-only"> {entry.path}</span></button><button className="btn btn-danger" type="button" disabled={isDisabled || blocked} onClick={() => removeEntry(entry)}><Trash2 size={16} aria-hidden="true" /><span className="sr-only">Delete {entry.path}</span></button></div></td></tr>)}</tbody></table></div>}
            {session.data.entries.filter((entry) => entry.id === revealed).map((entry) => <section key={entry.id} className="local-reveal" aria-label={`Decrypted ${entry.path}`}><h3>{entry.path}</h3><pre className="local-wrap" tabIndex={0} role="region" aria-label="Decrypted secret value">{entry.value}</pre><button className="btn" type="button" disabled={isDisabled} onClick={() => void run(async () => copy(entry.value))}><Copy size={16} aria-hidden="true" />Copy value</button></section>)}
          </section>
          <section className="panel" aria-labelledby="entry-title"><div className="panel-heading"><h3 id="entry-title">{editing ? 'Edit secret' : 'Add secret'}</h3></div><form onSubmit={(event) => void saveEntry(event)}><label>Secret path<input value={path} required maxLength={200} autoComplete="off" onChange={(event) => setPath(event.target.value)} disabled={isDisabled || blocked} /></label><label>Secret value<textarea aria-label="Secret value" value={value} maxLength={65536} rows={4} autoComplete="off" spellCheck={false} onChange={(event) => setValue(event.target.value)} disabled={isDisabled || blocked} /></label><div className="button-row"><button type="submit" className="btn btn-primary" disabled={isDisabled || blocked}><Plus size={16} aria-hidden="true" />Save secret</button>{editing && <button className="btn" type="button" onClick={() => { setEditing(undefined); setPath(''); setValue(''); }}>Cancel edit</button>}</div></form></section>
        </>}
        {session && section === 'Status' && <section className="panel" aria-labelledby="lock-title"><div className="panel-heading"><h3 id="lock-title">Lock settings</h3></div><div className="field"><label htmlFor="local-idle-minutes">Lock after inactivity</label><select id="local-idle-minutes" value={idleMinutes} onChange={(event) => setIdleMinutes(Number(event.target.value))}><option value={1}>1 minute</option><option value={5}>5 minutes</option><option value={15}>15 minutes</option></select></div><label className="check"><input type="checkbox" checked={hideLock} onChange={(event) => setHideLock(event.target.checked)} />Lock when this tab is hidden</label><p className="hint">Settings apply to this open page. Locking clears decrypted values, forms and recovery shares. Clipboard clearing depends on browser permission.</p></section>}
        {file && section === 'Status' && <section className="panel" aria-labelledby="delete-vault-title"><div className="panel-heading"><h3 id="delete-vault-title">Saved vault</h3></div><p className="panel-note">Export an encrypted backup before deleting the saved copy. Exported files are kept separately.</p><button className="btn btn-danger" type="button" disabled={isDisabled || blocked} onClick={() => {
          if (!window.confirm('Delete the saved encrypted vault from this browser? Keep an exported backup first. This cannot be undone.')) return;
          void run(async (operation) => { await persist(null, operation); lock(); setChanges(false); setStatus('Saved encrypted vault deleted. You can create or import another vault.'); });
        }}><Trash2 size={16} aria-hidden="true" />Delete vault</button></section>}
        {session && section === 'Keys' && <>
          <section className="panel" aria-labelledby="rotate-title"><div className="panel-heading"><h3 id="rotate-title">Rotate passphrase</h3></div><p className="panel-note">Re-wrap the same data key with a new salt and passphrase. Secret ciphertext stays unchanged. Older exported files still require their old passphrases.</p><form onSubmit={(event) => { event.preventDefault(); if (!file) return; void run(async (operation) => { if (nextPass !== confirmation) throw new Error('Passphrase confirmation does not match.'); const next = await rotatePassphrase(file, session, nextPass); await persist(next, operation); setNextPass(''); setConfirmation(''); setStatus('Passphrase rotated. Export a new encrypted backup.'); record('Passphrase rotated'); }); }}><label>New passphrase<input type="password" minLength={12} maxLength={1024} required autoComplete="new-password" value={nextPass} onChange={(event) => setNextPass(event.target.value)} disabled={isDisabled || blocked} /></label><label>Confirm new passphrase<input type="password" required autoComplete="new-password" value={confirmation} onChange={(event) => setConfirmation(event.target.value)} disabled={isDisabled || blocked} /></label><button className="btn btn-primary" type="submit" disabled={isDisabled || blocked}>Rotate passphrase</button></form></section>
          <section className="panel" aria-labelledby="shares-title"><div className="panel-heading"><h3 id="shares-title">Recovery shares</h3></div><p className="panel-note">Any 3 of 5 shares recover this vault without the passphrase. Keep them separately and apart from encrypted exports. Shares are never saved in this browser. Older share sets still recover the same data key. Use three shares from one set.</p><button type="button" className="btn" disabled={isDisabled} onClick={() => { if (file) setShares(recoveryShares(file, session)); }}>Create recovery shares</button>{shares.length > 0 && <><ol className="local-shares">{shares.map((share, index) => <li key={share}><label>Recovery share {index + 1}<textarea aria-label={`Recovery share ${index + 1}`} readOnly value={share} rows={3} spellCheck={false} /></label><button className="btn" type="button" disabled={isDisabled} onClick={() => void run(async () => copy(share))}>Copy share {index + 1}</button></li>)}</ol><button className="btn" type="button" onClick={() => setShares([])}>Hide recovery shares</button></>}</section>
        </>}
        {section === 'Leases' && <section className="panel"><h3>Local notebook</h3><p className="hint">This workspace does not issue temporary credentials. Sample data includes the server lease examples.</p></section>}
        {section === 'Audit' && <section className="panel"><h3>Session activity</h3><p className="hint">Only actions from this unlocked session. This list is cleared on lock and is not a permanent or tamper-evident audit trail.</p><ul className="local-audit">{audit.map((item, index) => <li key={index} className="mono">{item}</li>)}</ul></section>}
      </div>
      {dialog && <ImportVault returnFocus={opener} close={() => setDialog(false)} importFile={async (imported) => {
        const operation = epoch.current;
        if (blocked) throw new Error('Reload saved vault before importing over it.');
        if (imported.size > MAX_VAULT_BYTES) throw new Error(`${imported.name}: file must be at most 4 MiB.`);
        const incoming = parseVault(await imported.text(), imported.name);
        if (file && !window.confirm('Replace this saved encrypted vault? Export a backup first. This cannot be undone.')) return false;
        await persist(incoming, operation); lock(); setSection('Status'); setStatus('Encrypted vault imported. Unlock it with its passphrase or recovery shares.'); return true;
      }} />}
    </main>
  </div>;
}

function ImportVault({ close, importFile, returnFocus }: { close: () => void; importFile: (file: File) => Promise<boolean>; returnFocus: RefObject<HTMLButtonElement | null> }) {
  const root = useRef<HTMLDivElement>(null);
  const [selected, setSelected] = useState<File | null>(null);
  const [error, setError] = useState(''); const [busy, setBusy] = useState(false);
  useEffect(() => {
    const restoreOverflow = document.body.style.overflow; document.body.style.overflow = 'hidden'; root.current?.focus();
    const contain = () => { if (!root.current?.contains(document.activeElement)) root.current?.focus(); };
    document.addEventListener('focusin', contain);
    return () => { document.removeEventListener('focusin', contain); document.body.style.overflow = restoreOverflow; returnFocus.current?.focus(); };
  }, [returnFocus]);
  useEffect(() => { if (!root.current?.contains(document.activeElement)) root.current?.focus(); }, [busy]);
  return <div className="local-modal-backdrop"><div className="panel local-modal" role="dialog" aria-modal="true" aria-labelledby="import-title" tabIndex={-1} ref={root} onKeyDown={(event) => {
    if (event.key === 'Escape' && !busy) { event.preventDefault(); close(); }
    if (event.key === 'Tab') {
      const controls = Array.from(root.current?.querySelectorAll<HTMLElement>('button:not(:disabled), input:not(:disabled), [tabindex="0"]') ?? []);
      const first = controls[0]; const last = controls.at(-1);
      if (!first || !last) { event.preventDefault(); return; }
      if (event.shiftKey && (document.activeElement === first || document.activeElement === root.current)) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && (document.activeElement === last || document.activeElement === root.current)) { event.preventDefault(); first.focus(); }
    }
  }}><div className="panel-heading"><h3 id="import-title">Import encrypted vault</h3><button type="button" className="btn-icon" disabled={busy} aria-label="Close import" onClick={close}><X size={16} aria-hidden="true" /></button></div>
    <form onSubmit={(event) => { event.preventDefault(); if (!selected) { setError('Choose an encrypted vault JSON file.'); return; } setBusy(true); setError(''); void importFile(selected).then((imported) => { if (imported) close(); }).catch((reason) => setError(message(reason))).finally(() => setBusy(false)); }}>
      <div className="local-modal-scroll" role="region" tabIndex={0} aria-label="Encrypted vault import"><p className="panel-note">Choose a version 1 encrypted vault JSON file, up to 4 MiB. Import never unlocks or uploads it.</p><label>Encrypted vault JSON<input type="file" accept=".json,application/json" disabled={busy} onChange={(event) => setSelected(event.target.files?.[0] ?? null)} /></label>{error && <p className="danger-text" role="alert">{error}</p>}</div>
      <div className="button-row"><button className="btn" type="button" disabled={busy} onClick={close}>Cancel</button><button className="btn btn-primary" type="submit" disabled={busy}>Import vault</button></div>
    </form></div></div>;
}

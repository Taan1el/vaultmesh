import { webcrypto } from 'node:crypto';
import { act, cleanup, configure, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { LocalVault } from './LocalVault';
import { createVault, putEntry, recoverVault, recoveryShares, sealData, serializeVault, unlockVault, type VaultFile } from './vault';
import { axe } from '../test/axe';

const storage = vi.hoisted(() => ({ load: vi.fn(), save: vi.fn(), download: vi.fn() }));
vi.mock('./workspace', async (original) => ({ ...await original<object>(), loadWorkspaceSnapshot: storage.load, saveWorkspace: storage.save }));
vi.mock('./files', () => ({ downloadFile: storage.download }));
// Every create, unlock, rotate and import runs PBKDF2 at the real 600,000 iterations, which can take several
// seconds on a slow or busy machine. Wait for results longer than Testing Library's 1 second default, and give
// each test room for the several derivations it runs, instead of lowering the cost the product uses.
configure({ asyncUtilTimeout: 15_000 });
const KDF_TEST_TIMEOUT = 60_000;
const phrase = 'synthetic page passphrase';
function change(label: string, value: string) { fireEvent.change(screen.getByLabelText(label, { exact: true }), { target: { value } }); }
async function open(file: VaultFile | null = null) {
  storage.load.mockResolvedValue({ data: file, revision: file ? 1 : 0 });
  const view = render(<LocalVault />); await waitFor(() => expect(screen.queryByText('Loading encrypted workspace.')).not.toBeInTheDocument()); return view;
}
async function create() {
  change('Passphrase', phrase); change('Confirm passphrase', phrase);
  fireEvent.click(screen.getByRole('button', { name: 'Create vault' }));
  await screen.findByText('Vault unlocked.');
}
async function add() {
  change('Secret path', 'synthetic/path'); change('Secret value', 'synthetic plaintext');
  fireEvent.click(screen.getByRole('button', { name: 'Save secret' })); await screen.findByText('Secret encrypted and saved.');
}
beforeEach(() => {
  vi.stubGlobal('crypto', webcrypto); storage.load.mockReset(); storage.save.mockReset(); storage.download.mockReset();
  let revision = 0; storage.save.mockImplementation(async () => ++revision); sessionStorage.clear();
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals(); vi.useRealTimers(); });

describe('local encrypted notebook', { timeout: KDF_TEST_TIMEOUT }, () => {
  it('creates a saved vault, encrypts entries and exports only ciphertext', async () => {
    await open(); await create(); await add();
    expect(storage.save.mock.calls[0][1]).toEqual({ expectedRevision: 0 });
    expect(storage.save.mock.calls[1][1]).toEqual({ expectedRevision: 1 });
    const text = JSON.stringify(storage.save.mock.calls);
    expect(text).not.toContain('synthetic/path'); expect(text).not.toContain('synthetic plaintext'); expect(text).not.toContain(phrase);
    fireEvent.click(screen.getByRole('button', { name: 'Export vault' }));
    expect(storage.download.mock.calls[0][1]).toBe(serializeVault(storage.save.mock.calls[1][0]));
  });
  it('locks and clears values, edit forms and recovery shares', async () => {
    await open(); await create(); await add();
    fireEvent.click(screen.getByRole('button', { name: 'Inspect synthetic/path' })); expect(screen.getByText('synthetic plaintext')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Edit synthetic/path' })); expect(screen.getByLabelText('Secret value')).toHaveValue('synthetic plaintext');
    fireEvent.click(screen.getByRole('button', { name: /^Keys/ }));
    fireEvent.click(screen.getByRole('button', { name: 'Create recovery shares' })); expect((screen.getByLabelText('Recovery share 1') as HTMLTextAreaElement).value).toContain('vmrecovery-2:');
    fireEvent.click(screen.getByRole('button', { name: 'Lock vault' }));
    expect(screen.queryByText('synthetic/path')).not.toBeInTheDocument(); expect(screen.queryByDisplayValue('synthetic plaintext')).not.toBeInTheDocument(); expect(screen.queryByLabelText('Recovery share 1')).not.toBeInTheDocument();
    expect(screen.getByLabelText('Passphrase', { exact: true })).toHaveValue('');
  });
  it('auto-locks after inactivity and on hide, with a hide-lock opt-out', async () => {
    await open(); await create(); fireEvent.click(screen.getByRole('button', { name: /^Status/ }));
    vi.useFakeTimers();
    fireEvent.change(screen.getByLabelText('Lock after inactivity'), { target: { value: '1' } });
    fireEvent.click(screen.getByLabelText('Lock when this tab is hidden'));
    vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden');
    fireEvent(document, new Event('visibilitychange')); expect(screen.getByText('Lock settings')).toBeInTheDocument();
    await act(async () => { await vi.advanceTimersByTimeAsync(60000); });
    expect(screen.getByRole('heading', { name: 'Unlock encrypted vault' })).toBeInTheDocument();
    vi.useRealTimers();
  });
  it('locks immediately when hidden by default', async () => {
    await open(); await create(); vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden');
    fireEvent(document, new Event('visibilitychange'));
    expect(screen.getByRole('heading', { name: 'Unlock encrypted vault' })).toBeInTheDocument();
  });
  it('keeps the pending clipboard clear when the vault locks, then clears at the scheduled time', async () => {
    vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible'); vi.spyOn(document, 'hasFocus').mockReturnValue(true);
    let text = ''; const writeText = vi.fn(async (next: string) => { text = next; });
    vi.stubGlobal('navigator', Object.assign(Object.create(navigator), { clipboard: { writeText, readText: async () => text } }));
    await open(); await create(); await add();
    fireEvent.click(screen.getByRole('button', { name: 'Inspect synthetic/path' }));
    vi.useFakeTimers(); fireEvent.click(screen.getByRole('button', { name: 'Copy value' })); await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    expect(screen.getByText(/^Copied\./)).toBeInTheDocument();
    expect(text).toBe('synthetic plaintext');
    fireEvent.click(screen.getByRole('button', { name: 'Lock vault' }));
    expect(screen.getByRole('heading', { name: 'Unlock encrypted vault' })).toBeInTheDocument();
    expect(screen.getByText(/stays on the clipboard until its 30 second clear/)).toBeInTheDocument();
    expect(writeText).toHaveBeenCalledTimes(1); expect(text).toBe('synthetic plaintext');
    await act(async () => { await vi.advanceTimersByTimeAsync(29999); }); expect(text).toBe('synthetic plaintext');
    await act(async () => { await vi.advanceTimersByTimeAsync(1); }); expect(text).toBe('');
    vi.useRealTimers();
  });
  it('shows a notice when a due clipboard clear is rejected on a visible page', async () => {
    vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible'); vi.spyOn(document, 'hasFocus').mockReturnValue(true);
    const writeText = vi.fn(async (next: string) => { if (!next) throw new Error('Denied.'); });
    vi.stubGlobal('navigator', Object.assign(Object.create(navigator), { clipboard: { writeText } }));
    await open(); await create(); await add();
    fireEvent.click(screen.getByRole('button', { name: 'Inspect synthetic/path' }));
    vi.useFakeTimers(); fireEvent.click(screen.getByRole('button', { name: 'Copy value' })); await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    expect(screen.getByText(/^Copied\./)).toBeInTheDocument();
    await act(async () => { await vi.advanceTimersByTimeAsync(30000); });
    expect(screen.getByRole('alert')).toHaveTextContent('The clipboard could not be cleared');
    vi.useRealTimers();
  });
  it('retains saved ciphertext after wrong password or failed writes', async () => {
    const created = await createVault(phrase); await open(created.file);
    change('Passphrase', 'wrong synthetic phrase'); fireEvent.click(screen.getByRole('button', { name: 'Unlock vault' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Unable to unlock'); expect(storage.save).not.toHaveBeenCalled();
    change('Passphrase', phrase); fireEvent.click(screen.getByRole('button', { name: 'Unlock vault' })); await screen.findByText('Vault unlocked.');
    storage.save.mockRejectedValue(new Error('Storage quota exceeded.')); change('Secret path', 'new/path'); change('Secret value', 'not saved');
    fireEvent.click(screen.getByRole('button', { name: 'Save secret' })); expect(await screen.findByRole('alert')).toHaveTextContent('quota');
    expect(screen.getByText('No secrets yet. Add a path and value below.')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Export vault' })); expect(storage.download.mock.calls[0][1]).toBe(serializeVault(created.file)); created.session.key.fill(0);
  });
  it('blocks destructive writes when saved storage cannot be read', async () => {
    storage.load.mockRejectedValue(new Error('Unavailable.')); render(<LocalVault />);
    expect(await screen.findByRole('alert')).toHaveTextContent('Writes are blocked');
    expect(screen.getByRole('button', { name: 'Create vault' })).toBeDisabled(); expect(storage.save).not.toHaveBeenCalled();
  });
  it('preserves old data on malformed import and traps dialog focus after an error', async () => {
    const user = userEvent.setup(); await open(); await user.click(screen.getByRole('button', { name: 'Import vault' }));
    const dialog = screen.getByRole('dialog', { name: 'Import encrypted vault' });
    const bad = new File(['{'], 'broken.json', { type: 'application/json' }); Object.defineProperty(bad, 'text', { value: async () => '{' });
    await user.upload(within(dialog).getByLabelText('Encrypted vault JSON'), bad); await user.click(within(dialog).getByRole('button', { name: 'Import vault' }));
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('broken.json: JSON'); expect(storage.save).not.toHaveBeenCalled();
    await user.tab(); expect(dialog.contains(document.activeElement)).toBe(true); await user.keyboard('{Escape}');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); expect(screen.getByRole('button', { name: 'Import vault' })).toHaveFocus();
  });
  async function backup(entries: number, passphrase = 'imported synthetic phrase') {
    const created = await createVault(passphrase); let data = created.session.data;
    for (let index = 0; index < entries; index += 1) data = putEntry(data, `imported/path-${index}`, `imported value ${index}`);
    const file = await sealData(created.file, created.session.key, data); created.session.key.fill(0);
    const upload = new File([serializeVault(file)], 'backup.json', { type: 'application/json' });
    Object.defineProperty(upload, 'text', { value: async () => serializeVault(file) });
    return { file, upload };
  }
  async function importDialog(upload: File, passphrase: string) {
    const user = userEvent.setup(); await user.click(screen.getByRole('button', { name: 'Import vault' }));
    const dialog = screen.getByRole('dialog', { name: 'Import encrypted vault' });
    await user.upload(within(dialog).getByLabelText('Encrypted vault JSON'), upload);
    if (passphrase) await user.type(within(dialog).getByLabelText('Passphrase for this file'), passphrase);
    await user.click(within(dialog).getByRole('button', { name: 'Import vault' })); return { user, dialog };
  }
  it('keeps the saved vault when the imported file does not open with the given passphrase', async () => {
    const saved = await createVault(phrase); const { upload } = await backup(2); const confirm = vi.spyOn(window, 'confirm');
    await open(saved.file); const { dialog } = await importDialog(upload, 'wrong synthetic phrase');
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('Your saved vault was not changed');
    expect(storage.save).not.toHaveBeenCalled(); expect(confirm).not.toHaveBeenCalled();
    saved.session.key.fill(0);
  });
  it('asks for the passphrase before replacing anything', async () => {
    const saved = await createVault(phrase); const { upload } = await backup(1);
    await open(saved.file); const { dialog } = await importDialog(upload, '');
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('Enter the passphrase for backup.json');
    expect(storage.save).not.toHaveBeenCalled(); saved.session.key.fill(0);
  });
  it('states how many entries replace how many, and replaces only after confirmation', async () => {
    const { upload, file: incoming } = await backup(3); await open(); await create(); await add();
    const confirm = vi.spyOn(window, 'confirm').mockReturnValueOnce(false).mockReturnValueOnce(true);
    const { user, dialog } = await importDialog(upload, 'imported synthetic phrase');
    await waitFor(() => expect(confirm).toHaveBeenCalledTimes(1));
    expect(confirm.mock.calls[0][0]).toContain('the saved vault (1 entry) with backup.json (3 entries)');
    expect(storage.save).toHaveBeenCalledTimes(2); expect(dialog).toBeInTheDocument();
    await user.click(within(dialog).getByRole('button', { name: 'Import vault' }));
    await screen.findByText(/^Encrypted vault imported with 3 entries\./);
    expect(storage.save.mock.calls[2][0]).toEqual(incoming); expect(storage.save.mock.calls[2][1]).toEqual({ expectedRevision: 2 });
    expect(screen.getByRole('heading', { name: 'Unlock encrypted vault' })).toBeInTheDocument();
  });
  it('says the saved entries cannot be counted while the saved vault is locked', async () => {
    const saved = await createVault(phrase); const { upload } = await backup(0);
    await open(saved.file); const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false);
    await importDialog(upload, 'imported synthetic phrase'); await waitFor(() => expect(confirm).toHaveBeenCalledTimes(1));
    expect(confirm.mock.calls[0][0]).toContain('which is locked so its entries cannot be counted, with backup.json (0 entries)');
    saved.session.key.fill(0);
  });
  async function sharedBackup(entries: number) {
    const created = await createVault('imported synthetic phrase'); let data = created.session.data;
    for (let index = 0; index < entries; index += 1) data = putEntry(data, `imported/path-${index}`, `imported value ${index}`);
    const file = await sealData(created.file, created.session.key, data);
    const shares = recoveryShares(file, { key: created.session.key, data }); created.session.key.fill(0);
    const upload = new File([serializeVault(file)], 'backup.json', { type: 'application/json' });
    Object.defineProperty(upload, 'text', { value: async () => serializeVault(file) });
    return { file, upload, shares };
  }
  async function importWithShares(upload: File, shares: string[], next: string, confirmation = next) {
    const user = userEvent.setup(); await user.click(screen.getByRole('button', { name: 'Import vault' }));
    const dialog = screen.getByRole('dialog', { name: 'Import encrypted vault' });
    await user.upload(within(dialog).getByLabelText('Encrypted vault JSON'), upload);
    await user.selectOptions(within(dialog).getByLabelText('Open this file with'), 'shares');
    expect(within(dialog).queryByLabelText('Passphrase for this file')).not.toBeInTheDocument();
    fireEvent.change(within(dialog).getByLabelText('Recovery shares for this file, one per line'), { target: { value: shares.join('\n') } });
    fireEvent.change(within(dialog).getByLabelText('New passphrase for this file'), { target: { value: next } });
    fireEvent.change(within(dialog).getByLabelText('Confirm new passphrase for this file'), { target: { value: confirmation } });
    await user.click(within(dialog).getByRole('button', { name: 'Import vault' })); return { user, dialog };
  }
  it('imports a file with three recovery shares and a new passphrase, without its old passphrase', async () => {
    const saved = await createVault(phrase); const { file: incoming, upload, shares } = await sharedBackup(2);
    await open(saved.file); const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true);
    await importWithShares(upload, [shares[0], shares[2], shares[4]], 'synthetic new import phrase');
    await screen.findByText(/^Encrypted vault imported with 2 entries using recovery shares\./);
    expect(confirm.mock.calls[0][0]).toContain('which is locked so its entries cannot be counted, with backup.json (2 entries)');
    expect(storage.save).toHaveBeenCalledTimes(1); expect(storage.save.mock.calls[0][1]).toEqual({ expectedRevision: 1 });
    const stored = storage.save.mock.calls[0][0] as VaultFile;
    // Same vault and ciphertext, re-wrapped for the new passphrase only.
    expect(stored.id).toBe(incoming.id); expect(stored.payload).toEqual(incoming.payload); expect(stored.kdf.salt).not.toBe(incoming.kdf.salt);
    expect(JSON.stringify(storage.save.mock.calls)).not.toContain('imported value 0'); expect(JSON.stringify(storage.save.mock.calls)).not.toContain('synthetic new import phrase');
    expect((await unlockVault(stored, 'synthetic new import phrase')).data.entries.map((entry) => entry.value).sort()).toEqual(['imported value 0', 'imported value 1']);
    await expect(unlockVault(stored, 'imported synthetic phrase')).rejects.toThrow('Unable to unlock');
    const again = await recoverVault(stored, shares.slice(1, 4), 'another synthetic phrase'); expect(again.session.data.entries).toHaveLength(2); again.session.key.fill(0);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); expect(screen.getByRole('heading', { name: 'Unlock encrypted vault' })).toBeInTheDocument();
    saved.session.key.fill(0);
  });
  it('keeps the saved vault when import shares are from another vault, mistyped or paired with a bad new passphrase', async () => {
    const saved = await createVault(phrase); const { upload, shares } = await sharedBackup(1); const other = await sharedBackup(0);
    await open(saved.file); const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true);
    const { user, dialog } = await importWithShares(upload, [shares[0], shares[1], other.shares[0]], 'synthetic new import phrase');
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('Recovery share on line 3 belongs to a different vault');
    expect(within(dialog).getByRole('alert')).toHaveTextContent('Your saved vault was not changed');
    const typo = shares[2].slice(0, -1) + (shares[2].endsWith('0') ? '1' : '0');
    fireEvent.change(within(dialog).getByLabelText('Recovery shares for this file, one per line'), { target: { value: [shares[0], shares[1], typo].join('\n') } });
    await user.click(within(dialog).getByRole('button', { name: 'Import vault' }));
    await waitFor(() => expect(within(dialog).getByRole('alert')).toHaveTextContent('Recovery share on line 3 has a typo'));
    fireEvent.change(within(dialog).getByLabelText('Recovery shares for this file, one per line'), { target: { value: shares.slice(0, 3).join('\n') } });
    fireEvent.change(within(dialog).getByLabelText('Confirm new passphrase for this file'), { target: { value: 'a different synthetic phrase' } });
    await user.click(within(dialog).getByRole('button', { name: 'Import vault' }));
    await waitFor(() => expect(within(dialog).getByRole('alert')).toHaveTextContent('New passphrase confirmation does not match'));
    fireEvent.change(within(dialog).getByLabelText('New passphrase for this file'), { target: { value: 'aaaaaaaaaaaa' } });
    fireEvent.change(within(dialog).getByLabelText('Confirm new passphrase for this file'), { target: { value: 'aaaaaaaaaaaa' } });
    await user.click(within(dialog).getByRole('button', { name: 'Import vault' }));
    await waitFor(() => expect(within(dialog).getByRole('alert')).toHaveTextContent('one character repeated'));
    expect(storage.save).not.toHaveBeenCalled(); expect(confirm).not.toHaveBeenCalled(); expect(dialog).toBeInTheDocument();
    saved.session.key.fill(0);
  });
  it('has no axe violations in the import dialog when opening with recovery shares', async () => {
    const user = userEvent.setup(); const { container } = await open();
    await user.click(screen.getByRole('button', { name: 'Import vault' }));
    await user.selectOptions(screen.getByLabelText('Open this file with'), 'shares');
    expect(screen.getByLabelText('Recovery shares for this file, one per line')).toBeInTheDocument();
    expect((await axe(container)).violations).toEqual([]);
    await user.tab({ shift: true }); expect(screen.getByRole('dialog').contains(document.activeElement)).toBe(true);
  });
  it('does not delete an entry when confirmation is cancelled', async () => {
    await open(); await create(); await add(); vi.spyOn(window, 'confirm').mockReturnValueOnce(false).mockReturnValueOnce(true);
    fireEvent.click(screen.getByRole('button', { name: 'Delete synthetic/path' })); expect(storage.save).toHaveBeenCalledTimes(2);
    fireEvent.click(screen.getByRole('button', { name: 'Delete synthetic/path' })); await screen.findByText('Secret deleted.');
    expect(JSON.stringify(storage.save.mock.calls[2][0])).not.toContain('synthetic plaintext');
    expect(screen.getByText('No secrets yet. Add a path and value below.')).toBeInTheDocument();
  });
  it('confirms vault deletion and clears decrypted forms before creating another vault', async () => {
    await open(); await create(); await add();
    fireEvent.click(screen.getByRole('button', { name: /^Status/ }));
    vi.spyOn(window, 'confirm').mockReturnValueOnce(false).mockReturnValueOnce(true);
    fireEvent.click(screen.getByRole('button', { name: 'Delete vault' })); expect(storage.save).toHaveBeenCalledTimes(2);
    fireEvent.click(screen.getByRole('button', { name: 'Delete vault' }));
    await screen.findByText('Saved encrypted vault deleted. You can create or import another vault.');
    expect(storage.save.mock.calls[2]).toEqual([null, { expectedRevision: 2 }]);
    expect(screen.getByRole('button', { name: 'Create vault' })).toBeEnabled();
    expect(screen.getByRole('button', { name: 'Export vault' })).toBeDisabled();
    expect(screen.queryByText('synthetic/path')).not.toBeInTheDocument();
  });
  it('has no axe violations on locked, unlocked ledger, keys and import views', async () => {
    const { container } = await open(); expect((await axe(container)).violations).toEqual([]);
    await create(); await add(); expect((await axe(container)).violations).toEqual([]);
    fireEvent.click(screen.getByRole('button', { name: /^Keys/ })); expect((await axe(container)).violations).toEqual([]);
    fireEvent.click(screen.getByRole('button', { name: 'Import vault' })); expect((await axe(container)).violations).toEqual([]);
  });
  it('rejects stale-tab writes, locks plaintext and preserves the latest saved vault', async () => {
    const { WorkspaceConflictError } = await import('./workspace'); await open(); await create();
    storage.save.mockRejectedValue(new WorkspaceConflictError());
    change('Secret path', 'stale/path'); change('Secret value', 'stale plaintext'); fireEvent.click(screen.getByRole('button', { name: 'Save secret' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('another tab');
    expect(screen.getByRole('button', { name: 'Unlock vault' })).toBeDisabled();
    expect(screen.queryByDisplayValue('stale plaintext')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Reload saved vault' })).toBeEnabled();
  });
  async function openKeys() { fireEvent.click(screen.getByRole('button', { name: /^Keys/ })); }
  function rekeyForm(first: string, second = first) { change('Passphrase for the re-keyed vault', first); change('Confirm passphrase for the re-keyed vault', second); }
  it('re-keys the vault in one revision-checked save and says what stops working', async () => {
    await open(); await create(); await add(); await openKeys();
    fireEvent.click(screen.getByRole('button', { name: 'Create recovery shares' })); expect(screen.getByText(/^Share set/)).toBeInTheDocument();
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true);
    rekeyForm('synthetic rekeyed phrase'); fireEvent.click(screen.getByRole('button', { name: 'Re-key vault' }));
    await screen.findByText(/^Vault re-keyed\./);
    expect(confirm.mock.calls[0][0]).toContain('will not open the vault as it is from now on');
    expect(screen.getByRole('status')).toHaveTextContent('will not open the vault as it is now');
    expect(storage.save).toHaveBeenCalledTimes(3); expect(storage.save.mock.calls[2][1]).toEqual({ expectedRevision: 2 });
    const before = storage.save.mock.calls[1][0] as VaultFile; const after = storage.save.mock.calls[2][0] as VaultFile;
    expect(after.id).not.toBe(before.id);
    expect(JSON.stringify(after)).not.toContain('synthetic plaintext'); expect(JSON.stringify(storage.save.mock.calls)).not.toContain('synthetic rekeyed phrase');
    expect((await unlockVault(after, 'synthetic rekeyed phrase')).data.entries[0].value).toBe('synthetic plaintext');
    expect(screen.queryByLabelText('Recovery share 1')).not.toBeInTheDocument();
    expect(screen.getByLabelText('Passphrase for the re-keyed vault')).toHaveValue('');
    // The session carries on with the new key: a later save is sealed under it.
    fireEvent.click(screen.getByRole('button', { name: /^Secrets/ })); change('Secret path', 'after/rekey'); change('Secret value', 'later value');
    fireEvent.click(screen.getByRole('button', { name: 'Save secret' })); await waitFor(() => expect(storage.save).toHaveBeenCalledTimes(4));
    const later = storage.save.mock.calls[3][0] as VaultFile; expect(later.id).toBe(after.id);
    expect((await unlockVault(later, 'synthetic rekeyed phrase')).data.entries).toHaveLength(2);
  });
  it('does not re-key without confirmation or with a mismatched passphrase', async () => {
    await open(); await create(); await add(); await openKeys();
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false);
    rekeyForm('synthetic rekeyed phrase', 'another mismatch phrase'); fireEvent.click(screen.getByRole('button', { name: 'Re-key vault' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Passphrase confirmation does not match'); expect(confirm).not.toHaveBeenCalled();
    rekeyForm('synthetic rekeyed phrase'); fireEvent.click(screen.getByRole('button', { name: 'Re-key vault' }));
    await waitFor(() => expect(confirm).toHaveBeenCalledTimes(1)); expect(storage.save).toHaveBeenCalledTimes(2);
  });
  it('rejects a weak passphrase for the re-keyed vault before anything is saved', async () => {
    await open(); await create(); await add(); await openKeys(); vi.spyOn(window, 'confirm').mockReturnValue(true);
    rekeyForm('aaaaaaaaaaaa'); fireEvent.click(screen.getByRole('button', { name: 'Re-key vault' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('one character repeated'); expect(storage.save).toHaveBeenCalledTimes(2);
  });
  it('keeps the current key and vault when the re-key save is interrupted', async () => {
    await open(); await create(); await add(); await openKeys(); vi.spyOn(window, 'confirm').mockReturnValue(true);
    const saved = storage.save.mock.calls[1][0] as VaultFile; storage.save.mockRejectedValueOnce(new Error('Storage write was interrupted.'));
    rekeyForm('synthetic rekeyed phrase'); fireEvent.click(screen.getByRole('button', { name: 'Re-key vault' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('interrupted');
    expect(screen.getByRole('heading', { name: 'Re-key vault' })).toBeInTheDocument(); expect(screen.queryByText(/^Vault re-keyed\./)).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /^Secrets/ })); change('Secret path', 'after/failure'); change('Secret value', 'still the old key');
    fireEvent.click(screen.getByRole('button', { name: 'Save secret' })); await waitFor(() => expect(storage.save).toHaveBeenCalledTimes(4));
    const later = storage.save.mock.calls[3][0] as VaultFile; expect(later.id).toBe(saved.id);
    expect((await unlockVault(later, phrase)).data.entries).toHaveLength(2);
  });
  it('locks and keeps the saved vault when the re-key save finds a newer revision', async () => {
    const { WorkspaceConflictError } = await import('./workspace'); await open(); await create(); await openKeys(); vi.spyOn(window, 'confirm').mockReturnValue(true);
    storage.save.mockRejectedValueOnce(new WorkspaceConflictError());
    rekeyForm('synthetic rekeyed phrase'); fireEvent.click(screen.getByRole('button', { name: 'Re-key vault' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('another tab');
    expect(screen.getByRole('button', { name: 'Reload saved vault' })).toBeEnabled(); expect(screen.queryByDisplayValue('synthetic rekeyed phrase')).not.toBeInTheDocument();
  });
  it('shows no leftover key version, key count or lease labels in local mode', async () => {
    await open(); await create(); await add();
    expect(screen.queryByRole('button', { name: /^Leases/ })).not.toBeInTheDocument(); expect(screen.queryByText('Key version')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^Keys/ })).toHaveTextContent('Open');
    expect(screen.getAllByRole('columnheader').map((header) => header.textContent)).toEqual(['Index', 'Path', 'Updated', 'Actions']);
  });
  it('moves focus to the secret form when editing', async () => {
    await open(); await create(); await add();
    fireEvent.click(screen.getByRole('button', { name: 'Edit synthetic/path' }));
    expect(screen.getByLabelText('Secret path')).toHaveFocus(); expect(screen.getByRole('heading', { name: 'Edit secret' })).toBeInTheDocument();
  });
  it('rejects a trivially weak passphrase when creating a vault, with a specific message', async () => {
    await open(); change('Passphrase', 'abcdefghijkl'); change('Confirm passphrase', 'abcdefghijkl');
    fireEvent.click(screen.getByRole('button', { name: 'Create vault' })); expect(await screen.findByRole('alert')).toHaveTextContent('simple sequence');
    expect(storage.save).not.toHaveBeenCalled();
  });
  it('explains exactly what a lock clears', async () => {
    await open(); await create(); fireEvent.click(screen.getByRole('button', { name: 'Lock vault' }));
    expect(screen.getByRole('status')).toHaveTextContent('The key was zeroed and decrypted entries, form fields, recovery shares and the activity list were removed from this page.');
    expect(screen.getByRole('status')).not.toHaveTextContent('clipboard');
  });
});

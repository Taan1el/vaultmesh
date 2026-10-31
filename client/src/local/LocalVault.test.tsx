import { webcrypto } from 'node:crypto';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { LocalVault } from './LocalVault';
import { createVault, serializeVault, type VaultFile } from './vault';
import { axe } from '../test/axe';

const storage = vi.hoisted(() => ({ load: vi.fn(), save: vi.fn(), download: vi.fn() }));
vi.mock('./workspace', async (original) => ({ ...await original<object>(), loadWorkspaceSnapshot: storage.load, saveWorkspace: storage.save }));
vi.mock('./files', () => ({ downloadFile: storage.download }));
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

describe('local encrypted notebook', () => {
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
    fireEvent.click(screen.getByRole('button', { name: 'Create recovery shares' })); expect((screen.getByLabelText('Recovery share 1') as HTMLTextAreaElement).value).toContain('vmrecovery-1:');
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
});

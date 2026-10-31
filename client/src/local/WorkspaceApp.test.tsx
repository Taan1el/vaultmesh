import { cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { WorkspaceApp } from './WorkspaceApp';
import { axe } from '../test/axe';

const store = vi.hoisted(() => ({ load: vi.fn(), mode: vi.fn(), workspace: vi.fn() }));
vi.mock('./workspace', () => ({ loadMode: store.load, saveMode: store.mode, saveWorkspace: store.workspace }));
vi.mock('../services/api', () => ({ isDemoMode: true }));
vi.mock('../App', () => ({ App: () => <main aria-label="Sample console">Sample console</main> }));
vi.mock('./LocalVault', () => ({ LocalVault: () => <main aria-label="Encrypted workspace">Encrypted workspace</main> }));

beforeEach(() => { store.load.mockReset().mockResolvedValue('sample'); store.mode.mockReset().mockResolvedValue(undefined); store.workspace.mockReset(); });
afterEach(() => { cleanup(); vi.restoreAllMocks(); });
describe('sample and encrypted workspace selection', () => {
  it('remembers the workspace and confirms leaving it without writing encrypted contents', async () => {
    store.load.mockResolvedValue('workspace');
    const confirm = vi.spyOn(window, 'confirm').mockReturnValueOnce(false).mockReturnValueOnce(true);
    const user = userEvent.setup(); render(<WorkspaceApp />);
    await screen.findByRole('main', { name: 'Encrypted workspace' });
    await user.selectOptions(screen.getByLabelText('Data source'), 'sample');
    expect(screen.getByLabelText('Data source')).toHaveValue('workspace'); expect(store.mode).not.toHaveBeenCalled();
    await user.selectOptions(screen.getByLabelText('Data source'), 'sample');
    await screen.findByRole('main', { name: 'Sample console' });
    expect(confirm).toHaveBeenCalledTimes(2); expect(store.mode).toHaveBeenCalledWith('sample'); expect(store.workspace).not.toHaveBeenCalled();
  });
  it('keeps the current mode if saving the selection fails', async () => {
    const user = userEvent.setup(); render(<WorkspaceApp />); await screen.findByRole('main', { name: 'Sample console' });
    store.mode.mockRejectedValue(new Error('Storage unavailable.'));
    await user.selectOptions(screen.getByLabelText('Data source'), 'workspace');
    expect(await screen.findByRole('alert')).toHaveTextContent('Data source could not be saved');
    expect(screen.getByLabelText('Data source')).toHaveValue('sample'); expect(store.workspace).not.toHaveBeenCalled();
  });
  it('has an accessible source selector and reports storage-read failure', async () => {
    store.load.mockRejectedValue(new Error('Unavailable.'));
    const { container } = render(<WorkspaceApp />);
    await screen.findByRole('alert'); await waitFor(() => expect(screen.getByLabelText('Data source')).toBeEnabled());
    expect((await axe(container)).violations).toEqual([]);
    expect(screen.getByRole('combobox')).toHaveAccessibleName('Data source'); expect(store.workspace).not.toHaveBeenCalled();
  });
});

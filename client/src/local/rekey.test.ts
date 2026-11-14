// @vitest-environment node
import { IDBFactory, IDBObjectStore } from 'fake-indexeddb';
import { webcrypto } from 'node:crypto';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { VaultFile } from './vault';

const oldPhrase = 'synthetic old passphrase'; const newPhrase = 'synthetic new passphrase';
beforeEach(() => { vi.resetModules(); vi.restoreAllMocks(); vi.stubGlobal('indexedDB', new IDBFactory()); vi.stubGlobal('crypto', webcrypto); });

async function saved() {
  const vault = await import('./vault'); const store = await import('./workspace');
  const created = await vault.createVault(oldPhrase);
  created.session.data = vault.putEntry(created.session.data, 'synthetic/path', 'synthetic value');
  const file = await vault.sealData(created.file, created.session.key, created.session.data);
  await store.saveWorkspace(file, { expectedRevision: 0 });
  return { vault, store, file, session: created.session };
}

describe('saving a re-keyed vault', () => {
  it('rejects a wrong-revision write and leaves the saved vault openable with the old passphrase', async () => {
    const { vault, store, file, session } = await saved();
    const next = await vault.rekeyVault(file, session, newPhrase);
    await expect(store.saveWorkspace(next.file, { expectedRevision: 0 })).rejects.toThrow('another tab');
    const snapshot = await store.loadWorkspaceSnapshot<VaultFile>();
    expect(snapshot.revision).toBe(1); expect(snapshot.data).toEqual(file);
    expect((await vault.unlockVault(snapshot.data!, oldPhrase)).data).toEqual(session.data);
    await expect(vault.unlockVault(snapshot.data!, newPhrase)).rejects.toThrow('Unable to unlock');
    next.session.key.fill(0); session.key.fill(0);
  });
  it('keeps the old vault whole when the write is interrupted, then saves on retry', async () => {
    const { vault, store, file, session } = await saved();
    const next = await vault.rekeyVault(file, session, newPhrase);
    const original = IDBObjectStore.prototype.put;
    vi.spyOn(IDBObjectStore.prototype, 'put').mockImplementationOnce(function (this: IDBObjectStore, ...args) { const result = original.apply(this, args); this.transaction.abort(); return result; });
    await expect(store.saveWorkspace(next.file, { expectedRevision: 1 })).rejects.toThrow();
    const kept = await store.loadWorkspaceSnapshot<VaultFile>();
    expect(kept.revision).toBe(1); expect(kept.data).toEqual(file);
    expect((await vault.unlockVault(kept.data!, oldPhrase)).data).toEqual(session.data);
    expect(await store.saveWorkspace(next.file, { expectedRevision: 1 })).toBe(2);
    const stored = (await store.loadWorkspaceSnapshot<VaultFile>()).data!;
    expect(stored.id).toBe(next.file.id); expect((await vault.unlockVault(stored, newPhrase)).data).toEqual(session.data);
    // The earlier export still opens its own contents with the old passphrase.
    expect((await vault.unlockVault(file, oldPhrase)).data).toEqual(session.data);
    next.session.key.fill(0); session.key.fill(0);
  });
});

// @vitest-environment node
import { IDBFactory, IDBObjectStore } from 'fake-indexeddb';
import { webcrypto } from 'node:crypto';
import { beforeEach, describe, expect, it, vi } from 'vitest';

beforeEach(() => { vi.resetModules(); vi.restoreAllMocks(); vi.stubGlobal('indexedDB', new IDBFactory()); vi.stubGlobal('crypto', webcrypto); });
describe('encrypted storage isolation', () => {
  it('persists only encrypted envelopes and leaves them intact across sample resets and module reload', async () => {
    const { createVault, putEntry, sealData, unlockVault } = await import('./vault');
    const store = await import('./workspace');
    const created = await createVault('synthetic storage phrase');
    const data = putEntry(created.session.data, 'private-path-marker', 'private-value-marker');
    const encrypted = await sealData(created.file, created.session.key, data);
    const put = vi.spyOn(IDBObjectStore.prototype, 'put');
    await store.saveWorkspace(encrypted, { expectedRevision: 0 });
    await store.saveMode('sample'); await store.saveMode('workspace');
    const storedCalls = JSON.stringify(put.mock.calls);
    for (const sensitive of ['private-path-marker', 'private-value-marker', 'synthetic storage phrase']) expect(storedCalls).not.toContain(sensitive);
    vi.resetModules(); const restored = await import('./workspace');
    const snapshot = await restored.loadWorkspaceSnapshot<typeof encrypted>();
    expect(snapshot.revision).toBe(1); expect(await restored.loadMode()).toBe('workspace');
    expect((await unlockVault(snapshot.data!, 'synthetic storage phrase')).data).toEqual(data);
    created.session.key.fill(0);
  });
  it('rejects stale writes across independent tabs, including stale deletion', async () => {
    const one = await import('./workspace');
    await one.saveWorkspace({ ciphertext: 'saved' }, { expectedRevision: 0 });
    vi.resetModules(); const two = await import('./workspace');
    await two.saveWorkspace({ ciphertext: 'newer' }, { expectedRevision: 1 });
    await expect(one.saveWorkspace(null, { expectedRevision: 1 })).rejects.toThrow('another tab');
    expect(await one.loadWorkspace()).toEqual({ ciphertext: 'newer' });
    expect((await one.loadWorkspaceSnapshot()).revision).toBe(2);
  });
  it('keeps prior ciphertext after an aborted write and can recover', async () => {
    const store = await import('./workspace');
    await store.saveWorkspace({ ciphertext: 'prior' });
    const original = IDBObjectStore.prototype.put;
    vi.spyOn(IDBObjectStore.prototype, 'put').mockImplementationOnce(function (this: IDBObjectStore, ...args) { const result = original.apply(this, args); this.transaction.abort(); return result; });
    await expect(store.saveWorkspace({ ciphertext: 'failed' }, { expectedRevision: 1 })).rejects.toThrow();
    expect(await store.loadWorkspace()).toEqual({ ciphertext: 'prior' });
    await store.saveWorkspace({ ciphertext: 'recovered' }, { expectedRevision: 1 });
    expect(await store.loadWorkspace()).toEqual({ ciphertext: 'recovered' });
  });
});

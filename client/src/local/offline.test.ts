import { describe, expect, it, vi } from 'vitest';
import { createUpdateStore, shouldReload, updateWaiting } from './offline';

describe('update notice state', () => {
  it('reports an update only for a controlled page with a waiting worker', () => {
    const waiting = { waiting: {} as ServiceWorker };
    expect(updateWaiting(waiting, true)).toBe(true);
    expect(updateWaiting(waiting, false)).toBe(false);
    expect(updateWaiting({ waiting: null }, true)).toBe(false);
    expect(updateWaiting(undefined, true)).toBe(false);
  });
  it('reloads once, and only after someone asked for the update', () => {
    expect(shouldReload(false, false)).toBe(false);
    expect(shouldReload(true, false)).toBe(true);
    expect(shouldReload(true, true)).toBe(false);
  });
  it('tells subscribers only when the state changes', () => {
    const store = createUpdateStore(); const listener = vi.fn(); const stop = store.subscribe(listener);
    expect(store.get()).toBe(false);
    store.set(false); expect(listener).not.toHaveBeenCalled();
    store.set(true); expect(store.get()).toBe(true); expect(listener).toHaveBeenCalledTimes(1);
    store.set(true); expect(listener).toHaveBeenCalledTimes(1);
    stop(); store.set(false); expect(listener).toHaveBeenCalledTimes(1);
  });
});

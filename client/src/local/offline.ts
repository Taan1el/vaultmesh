/** Whether a newer service worker is installed and waiting. Only an already controlled page has an older worker to replace. */
export function updateWaiting(registration: Pick<ServiceWorkerRegistration, 'waiting'> | undefined, controlled: boolean): boolean {
  return controlled && Boolean(registration?.waiting);
}

/** The page reloads once, and only after someone chose to update. The first worker taking control must not reload it. */
export function shouldReload(requested: boolean, reloading: boolean): boolean {
  return requested && !reloading;
}

export interface UpdateStore { get(): boolean; set(ready: boolean): void; subscribe(listener: () => void): () => void }

export function createUpdateStore(): UpdateStore {
  let ready = false;
  const listeners = new Set<() => void>();
  return {
    get: () => ready,
    set(next) { if (next !== ready) { ready = next; listeners.forEach((listener) => listener()); } },
    subscribe(listener) { listeners.add(listener); return () => { listeners.delete(listener); }; },
  };
}

export const updates = createUpdateStore();
let registration: ServiceWorkerRegistration | undefined;
let reloadRequested = false;
let reloading = false;

function refresh() {
  updates.set(updateWaiting(registration, Boolean(navigator.serviceWorker.controller)));
}

/** Asks the waiting worker to take over. The page reloads when it does. */
export function applyUpdate(): boolean {
  const waiting = registration?.waiting;
  if (!waiting) return false;
  reloadRequested = true;
  waiting.postMessage({ type: 'SKIP_WAITING' });
  return true;
}

export function registerOffline(): void {
  if (import.meta.env.MODE !== 'pages' || !('serviceWorker' in navigator)) return;

  const register = () => {
    navigator.serviceWorker.addEventListener('controllerchange', () => {
      if (shouldReload(reloadRequested, reloading)) { reloading = true; window.location.reload(); }
    });
    void navigator.serviceWorker.register(`${import.meta.env.BASE_URL}sw.js`, {
      scope: import.meta.env.BASE_URL,
    }).then((registered) => {
      registration = registered;
      refresh();
      registered.addEventListener('updatefound', () => {
        const installing = registered.installing;
        installing?.addEventListener('statechange', () => { if (installing.state === 'installed') refresh(); });
      });
    }).catch((error: unknown) => {
      console.error('Offline storage could not start.', error);
    });
  };

  if (document.readyState === 'complete') register();
  else window.addEventListener('load', register, { once: true });
}

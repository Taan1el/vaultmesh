import { useSyncExternalStore } from 'react';
import { applyUpdate, updates, type UpdateStore } from './offline';

export function UpdateNotice({ store = updates, apply = applyUpdate }: { store?: UpdateStore; apply?: () => boolean }) {
  const ready = useSyncExternalStore(store.subscribe, store.get);
  if (!ready) return null;
  return <div className="local-source local-update" role="status"><p>A new version is ready.</p><button className="btn" type="button" onClick={() => { apply(); }}>Reload</button></div>;
}

export type WorkspaceMode = 'sample' | 'workspace';

const DATABASE_NAME = 'vaultmesh-local';
const DATABASE_VERSION = 1;
const STORE_NAME = 'settings';
const WORKSPACE_KEY = 'workspace';
const MODE_KEY = 'mode';

interface WorkspaceRecord<T> {
  version: 1;
  data: T;
  revision?: number;
}

export class WorkspaceConflictError extends Error {
  constructor() {
    super('Saved vault changed in another tab. Reload the saved vault before making more changes.');
    this.name = 'WorkspaceConflictError';
  }
}

type Migration = (database: IDBDatabase, transaction: IDBTransaction) => void;

// Add one migration per database version. IndexedDB applies the whole upgrade
// transaction atomically, preserving existing workspace records on failure.
const migrations: Record<number, Migration> = {
  1: (database) => {
    database.createObjectStore(STORE_NAME);
  },
};

let databasePromise: Promise<IDBDatabase> | undefined;
let operations: Promise<void> = Promise.resolve();

function openDatabase(): Promise<IDBDatabase> {
  if (databasePromise) return databasePromise;

  databasePromise = new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open(DATABASE_NAME, DATABASE_VERSION);
    let blocked = false;
    request.onupgradeneeded = (event) => {
      const transaction = request.transaction;
      if (!transaction) return;
      for (let version = event.oldVersion + 1; version <= DATABASE_VERSION; version += 1) {
        migrations[version]?.(request.result, transaction);
      }
    };
    request.onerror = () => reject(request.error ?? new Error('Browser storage could not open.'));
    request.onblocked = () => {
      blocked = true;
      reject(new Error('Close other VaultMesh tabs to update browser storage.'));
    };
    request.onsuccess = () => {
      const database = request.result;
      if (blocked) {
        database.close();
        return;
      }
      database.onversionchange = () => {
        database.close();
        databasePromise = undefined;
      };
      database.onclose = () => { databasePromise = undefined; };
      resolve(database);
    };
  }).catch((error: unknown) => {
    databasePromise = undefined;
    throw error;
  });

  return databasePromise;
}

function serialize<T>(operation: () => Promise<T>): Promise<T> {
  const result = operations.then(operation);
  operations = result.then(() => undefined, () => undefined);
  return result;
}

function storageError(transaction: IDBTransaction, request: IDBRequest | undefined, message: string): DOMException | Error {
  return transaction.error ?? (request?.readyState === 'done' ? request.error : null) ?? new Error(message);
}

async function readRecord<T>(key: string): Promise<T | undefined> {
  const database = await openDatabase();
  return new Promise<T | undefined>((resolve, reject) => {
    const transaction = database.transaction(STORE_NAME, 'readonly');
    const request = transaction.objectStore(STORE_NAME).get(key);
    let value: T | undefined;
    request.onsuccess = () => { value = request.result as T | undefined; };
    transaction.oncomplete = () => resolve(value);
    transaction.onabort = () => reject(storageError(transaction, request, 'Browser storage read failed.'));
    transaction.onerror = () => reject(storageError(transaction, request, 'Browser storage read failed.'));
  });
}

async function writeRecords(records: Array<{ key: string; value?: unknown }>): Promise<void> {
  const database = await openDatabase();
  return new Promise<void>((resolve, reject) => {
    const transaction = database.transaction(STORE_NAME, 'readwrite');
    const store = transaction.objectStore(STORE_NAME);
    let request: IDBRequest | undefined;
    transaction.oncomplete = () => resolve();
    transaction.onabort = () => reject(storageError(transaction, request, 'Browser storage write failed.'));
    transaction.onerror = () => reject(storageError(transaction, request, 'Browser storage write failed.'));
    try {
      for (const { key, value } of records) {
        request = value === undefined ? store.delete(key) : store.put(value, key);
      }
    } catch (error: unknown) {
      transaction.abort();
      reject(error);
    }
  });
}

function recordRevision(record: WorkspaceRecord<unknown> | undefined): number {
  if (record?.revision === undefined) return 0;
  if (!Number.isSafeInteger(record.revision) || record.revision < 0) {
    throw new Error('Saved browser workspace has an invalid revision.');
  }
  return record.revision;
}

function validateRecord(record: unknown): asserts record is WorkspaceRecord<unknown> | undefined {
  if (record !== undefined && (!record || typeof record !== 'object'
    || (record as WorkspaceRecord<unknown>).version !== 1 || !Object.hasOwn(record, 'data'))) {
    throw new Error('Saved browser workspace has an unsupported format. Import a backup to recover it.');
  }
}

export function loadWorkspaceSnapshot<T>(): Promise<{ data: T | null; revision: number }> {
  return serialize(async () => {
    const record = await readRecord<WorkspaceRecord<T>>(WORKSPACE_KEY);
    validateRecord(record);
    return { data: record?.data ?? null, revision: recordRevision(record) };
  });
}

export function loadWorkspace<T>(): Promise<T | null> {
  return loadWorkspaceSnapshot<T>().then((snapshot) => snapshot.data);
}

export function saveWorkspace<T>(data: T, options?: { mode?: WorkspaceMode; expectedRevision?: number }): Promise<number> {
  // Capture the call's value before it waits behind an earlier write.
  try {
    const record: WorkspaceRecord<T> = { version: 1, data: structuredClone(data) };
    const expectedRevision = options?.expectedRevision;
    if (expectedRevision !== undefined && (!Number.isSafeInteger(expectedRevision) || expectedRevision < 0)) {
      throw new Error('Expected workspace revision must be a non-negative safe integer.');
    }
    const mode = options?.mode;
    return serialize(async () => {
      const database = await openDatabase();
      return new Promise<number>((resolve, reject) => {
        // IndexedDB serializes overlapping readwrite transactions across tabs.
        // Check the revision and replace the key in this same transaction.
        const transaction = database.transaction(STORE_NAME, 'readwrite');
        const store = transaction.objectStore(STORE_NAME);
        const read = store.get(WORKSPACE_KEY);
        let failure: unknown;
        let revision = 0;
        transaction.oncomplete = () => resolve(revision);
        transaction.onabort = () => reject(failure ?? storageError(transaction, read, 'Browser storage write failed.'));
        transaction.onerror = () => reject(failure ?? storageError(transaction, read, 'Browser storage write failed.'));
        read.onsuccess = () => {
          try {
            const current = read.result as WorkspaceRecord<unknown> | undefined;
            if (expectedRevision !== undefined) validateRecord(current);
            const currentRevision = recordRevision(current);
            if (expectedRevision !== undefined && expectedRevision !== currentRevision) throw new WorkspaceConflictError();
            revision = currentRevision + 1;
            if (!Number.isSafeInteger(revision)) throw new Error('Saved browser workspace revision limit reached.');
            store.put({ ...record, revision }, WORKSPACE_KEY);
            if (mode) store.put(mode, MODE_KEY);
          } catch (error: unknown) {
            failure = error;
            transaction.abort();
          }
        };
      });
    });
  } catch (error: unknown) {
    return Promise.reject(error);
  }
}

export function clearWorkspace(): Promise<void> {
  // Keep the revision after clearing so an older tab cannot match a reused one.
  return saveWorkspace(null).then(() => undefined);
}

export function loadMode(): Promise<WorkspaceMode> {
  return serialize(async () => {
    const mode = await readRecord<WorkspaceMode>(MODE_KEY);
    return mode === 'workspace' ? 'workspace' : 'sample';
  });
}

export function saveMode(mode: WorkspaceMode): Promise<void> {
  return serialize(() => writeRecords([{ key: MODE_KEY, value: mode }]));
}

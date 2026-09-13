import supertest from 'supertest';
import { createApp } from '../src/app.js';

export type TestApp = ReturnType<typeof createApp>;

// Each test gets a fresh in-memory vault. Call close() in afterEach.
export function createTestApp(dbPath = ':memory:') {
  const instance = createApp(dbPath);
  const request = supertest(instance.app);
  const close = () => {
    instance.service.destroy();
    instance.db.close();
  };
  return { ...instance, request, close };
}

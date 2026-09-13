import supertest from 'supertest';
import { createApp } from '../src/app.js';

export type TestApp = ReturnType<typeof createApp>;

// Each test gets a fresh vault (in memory unless a path is given). Call close() in afterEach.
// Requests default to a JSON content type, like the dashboard sends.
export function createTestApp(dbPath = ':memory:') {
  const instance = createApp(dbPath);
  const request = supertest.agent(instance.app).set('Content-Type', 'application/json');
  const close = () => {
    instance.service.destroy();
    instance.db.close();
  };
  return { ...instance, request, close };
}

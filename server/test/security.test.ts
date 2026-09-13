import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import supertest from 'supertest';
import { createTestApp } from './helpers.js';

describe('HTTP hardening', () => {
  let t: ReturnType<typeof createTestApp>;

  beforeEach(() => {
    t = createTestApp();
  });

  afterEach(() => {
    t.close();
  });

  it('sends no CORS headers, so other origins cannot read API responses', async () => {
    const res = await supertest(t.app).get('/api/secrets').set('Origin', 'https://attacker.example');
    expect(res.status).toBe(200);
    expect(res.headers['access-control-allow-origin']).toBeUndefined();

    const preflight = await supertest(t.app)
      .options('/api/vault/seal')
      .set('Origin', 'https://attacker.example')
      .set('Access-Control-Request-Method', 'POST');
    expect(preflight.headers['access-control-allow-origin']).toBeUndefined();
  });

  it.each([
    ['no content type', undefined],
    ['a form post', 'application/x-www-form-urlencoded'],
    ['a text/plain post', 'text/plain'],
  ])('rejects POST with %s and changes nothing', async (_label, contentType) => {
    const req = supertest(t.app).post('/api/vault/seal');
    const res = contentType ? await req.set('Content-Type', contentType).send('x=1') : await req;
    expect(res.status).toBe(415);
    expect(res.body.error).toMatch(/application\/json/);
    expect((await t.request.get('/api/vault/status')).body.status).toBe('UNSEALED');
  });

  it('accepts JSON POSTs with an empty body', async () => {
    const res = await supertest(t.app).post('/api/vault/seal').set('Content-Type', 'application/json');
    expect(res.status).toBe(200);
    expect(res.body.state.status).toBe('SEALED');
  });

  it('marks API responses as not cacheable and hides the framework header', async () => {
    const res = await t.request.get('/api/secrets/secret/production/database');
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['x-powered-by']).toBeUndefined();
  });

  it('does not require a content type for reads and deletes', async () => {
    expect((await supertest(t.app).get('/api/vault/status')).status).toBe(200);
    expect((await supertest(t.app).delete('/api/secrets/secret/payments/gateway')).status).toBe(200);
  });
});

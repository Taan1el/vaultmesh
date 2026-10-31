// @vitest-environment node
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { build, resolveConfig } from 'vite';
import { LOCAL_CSP } from '../../localBuild.js';

const clientRoot = fileURLToPath(new URL('../../', import.meta.url));
let output: string;
let html: string;
let worker: string;
let files: string[];

async function listFiles(directory: string, prefix = ''): Promise<string[]> {
  const entries = await readdir(directory, { withFileTypes: true });
  const results = await Promise.all(entries.map((entry) => entry.isDirectory()
    ? listFiles(path.join(directory, entry.name), `${prefix}${entry.name}/`)
    : [`${prefix}${entry.name}`]));
  return results.flat();
}

beforeAll(async () => {
  output = await mkdtemp(path.join(tmpdir(), 'vaultmesh-local-build-'));
  await build({ root: clientRoot, mode: 'pages', logLevel: 'silent', build: { outDir: output, emptyOutDir: true } });
  html = await readFile(path.join(output, 'index.html'), 'utf8');
  worker = await readFile(path.join(output, 'sw.js'), 'utf8');
  files = await listFiles(output);
}, 30_000);

afterAll(async () => {
  if (!output) return;
  const resolved = path.resolve(output);
  if (path.dirname(resolved) !== path.resolve(tmpdir()) || !path.basename(resolved).startsWith('vaultmesh-local-build-')) {
    throw new Error('Build test output is outside its temporary directory.');
  }
  await rm(resolved, { recursive: true, force: true });
});

describe('Pages local app build', () => {
  it('places the exact CSP before resources and uses no remote resources', () => {
    const content = html.match(/http-equiv="Content-Security-Policy" content="([^"]+)"/)?.[1];
    expect(content?.replaceAll('&#39;', "'")).toBe(LOCAL_CSP);
    expect(html.indexOf('Content-Security-Policy')).toBeLessThan(html.indexOf('<script'));
    expect(html).not.toMatch(/(?:src|href|content)\s*=\s*["'](?:https?:)?\/\//i);
    expect(html).not.toContain('og:url');
    expect(html).toContain('data:image/svg+xml,');
  });

  it('keeps the Pages CSP plugin out of development', async () => {
    const config = await resolveConfig({ root: clientRoot, mode: 'development' }, 'serve');
    expect(config.plugins.some((plugin) => plugin.name === 'local-first-build')).toBe(false);
  });

  it('emits a standalone manifest and full-size PNG icons', async () => {
    const manifest = JSON.parse(await readFile(path.join(output, 'manifest.webmanifest'), 'utf8'));
    expect(manifest).toMatchObject({ start_url: '/vaultmesh/', scope: '/vaultmesh/', display: 'standalone', theme_color: '#183d32', background_color: '#183d32' });
    for (const size of [192, 512]) {
      expect(manifest.icons).toContainEqual({ src: `/vaultmesh/icon-${size}.png`, sizes: `${size}x${size}`, type: 'image/png', purpose: 'any maskable' });
      const icon = await readFile(path.join(output, `icon-${size}.png`));
      expect(icon.subarray(0, 8)).toEqual(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]));
      expect(icon.readUInt32BE(16)).toBe(size);
      expect(icon.readUInt32BE(20)).toBe(size);
    }
  });

  it('precaches every emitted file, fonts, its worker and the base page', () => {
    const match = worker.match(/const PRECACHE = (\[[^;]+\]);/);
    expect(match).not.toBeNull();
    const precache: string[] = JSON.parse(match![1]);
    expect(precache).toContain('/vaultmesh/');
    for (const file of files) expect(precache).toContain(`/vaultmesh/${file}`);
    expect(precache.some((file) => file.endsWith('.woff2'))).toBe(true);

    expect(precache).toContain('/vaultmesh/manifest.webmanifest');
    expect(precache).toContain('/vaultmesh/sw.js');
    expect(worker).toMatch(/const CACHE_NAME = CACHE_PREFIX \+ "[0-9a-f]{16}";/);
  });

  it('emits every font as a file allowed by the policy', async () => {
    let faces = 0;
    for (const file of files.filter((name) => name.endsWith('.css'))) {
      const css = await readFile(path.join(output, file), 'utf8');
      for (const face of css.matchAll(/@font-face\{[^}]+\}/g)) {
        faces += 1;
        expect(face[0]).not.toMatch(/url\(["']?data:/i);
      }
    }
    expect(faces).toBeGreaterThan(0);
  });

  it('serves cached pages offline and deletes only this app\'s older caches', async () => {
    const handlers: Record<string, (event: unknown) => void> = {};
    const cachedResponse = { body: 'cached page' };
    const deleted: string[] = [];
    const match = worker.match(/const CACHE_PREFIX = ("[^;]+);/);
    const prefix: string = JSON.parse(match![1]);
    const cache = { addAll: vi.fn(async () => undefined), match: async () => cachedResponse };
    const skipWaiting = vi.fn(async () => undefined);
    const context = {
      URL,
      caches: { open: async () => cache, keys: async () => [`${prefix}old`, 'another-app-cache'], delete: async (key: string) => { deleted.push(key); } },
      fetch: async () => { throw new Error('Server is off.'); },
      self: { location: { origin: 'https://local.test' }, addEventListener: (name: string, callback: (event: unknown) => void) => { handlers[name] = callback; }, skipWaiting, clients: { claim: async () => undefined } },
    };
    vm.runInNewContext(worker, context);
    let installation: Promise<void> | undefined;
    handlers.install({ waitUntil: (result: Promise<void>) => { installation = result; } });
    await installation;
    expect(cache.addAll).toHaveBeenCalled();
    expect(skipWaiting).not.toHaveBeenCalled();
    let response: Promise<unknown> | undefined;
    handlers.fetch({ request: { method: 'GET', url: 'https://local.test/vaultmesh/', mode: 'navigate' }, respondWith: (result: Promise<unknown>) => { response = result; } });
    expect(await response).toBe(cachedResponse);
    const forbiddenResponse = vi.fn();
    for (const url of ['https://outside.test/vaultmesh/', 'https://local.test/another-app/']) {
      handlers.fetch({ request: { method: 'GET', url, mode: 'navigate' }, respondWith: forbiddenResponse });
    }
    expect(forbiddenResponse).not.toHaveBeenCalled();
    let activation: Promise<void> | undefined;
    handlers.activate({ waitUntil: (result: Promise<void>) => { activation = result; } });
    await activation;
    expect(deleted).toEqual([`${prefix}old`]);
  });
});

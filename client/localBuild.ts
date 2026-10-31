import { createHash } from 'node:crypto';
import { deflateSync } from 'node:zlib';
import type { Plugin, Rollup } from 'vite';

export const LOCAL_CSP = "default-src 'self'; connect-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; font-src 'self'; script-src 'self'; base-uri 'self'; form-action 'none'";

interface LocalBuildOptions {
  base: string;
  name: string;
  id: string;
  description: string;
  themeColor?: string;
}

function checksum(data: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of data) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function pngChunk(type: string, data: Buffer): Buffer {
  const name = Buffer.from(type);
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(checksum(Buffer.concat([name, data])));
  return Buffer.concat([length, name, data, crc]);
}

// The existing shield and keyhole, inset inside the safe area for masked icons.
function documentIcon(size: number): Buffer {
  const paper = [238, 240, 234];
  const ink = [24, 61, 50];
  const polygon = [[12, 1], [3, 5], [3, 11], [4, 16], [7, 20], [12, 23], [17, 20], [20, 16], [21, 11], [21, 5]];
  const pixels = Buffer.alloc((size * 4 + 1) * size);
  for (let y = 0; y < size; y += 1) {
    for (let x = 0; x < size; x += 1) {
      const sourceX = ((x + 0.5) / size - 0.2) / 0.6 * 24;
      const sourceY = ((y + 0.5) / size - 0.2) / 0.6 * 24;
      let body = false;
      for (let i = 0, j = polygon.length - 1; i < polygon.length; j = i++) {
        const [xi, yi] = polygon[i]; const [xj, yj] = polygon[j];
        if ((yi > sourceY) !== (yj > sourceY) && sourceX < (xj - xi) * (sourceY - yi) / (yj - yi) + xi) body = !body;
      }
      const keyhole = Math.hypot(sourceX - 12, sourceY - 10) <= 3 || (sourceX >= 11 && sourceX <= 13 && sourceY >= 10 && sourceY <= 15);
      const opacity = body && !keyhole ? 1 : 0;
      const offset = y * (size * 4 + 1) + 1 + x * 4;
      for (let channel = 0; channel < 3; channel += 1) {
        pixels[offset + channel] = Math.round(paper[channel] * (1 - opacity) + ink[channel] * opacity);
      }
      pixels[offset + 3] = 255;
    }
  }
  const header = Buffer.alloc(13);
  header.writeUInt32BE(size, 0);
  header.writeUInt32BE(size, 4);
  header[8] = 8;
  header[9] = 6;
  return Buffer.concat([
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
    pngChunk('IHDR', header),
    pngChunk('IDAT', deflateSync(pixels)),
    pngChunk('IEND', Buffer.alloc(0)),
  ]);
}

function assetBytes(asset: Rollup.OutputAsset | Rollup.OutputChunk): string | Uint8Array {
  return asset.type === 'chunk' ? asset.code : asset.source;
}

function serviceWorker(cachePrefix: string, version: string, base: string, files: string[]): string {
  return `const CACHE_PREFIX = ${JSON.stringify(cachePrefix)};
const CACHE_NAME = CACHE_PREFIX + ${JSON.stringify(version)};
const BASE = ${JSON.stringify(base)};
const PRECACHE = ${JSON.stringify(files)};

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(CACHE_NAME).then(async (cache) => {
    try {
      await cache.addAll(PRECACHE);
    } catch (error) {
      await caches.delete(CACHE_NAME);
      throw error;
    }
  }));
});

self.addEventListener('activate', (event) => {
  event.waitUntil(caches.keys().then(async (keys) => {
    await Promise.all(keys.filter((key) => key.startsWith(CACHE_PREFIX) && key !== CACHE_NAME).map((key) => caches.delete(key)));
    await self.clients.claim();
  }));
});

self.addEventListener('fetch', (event) => {
  const request = event.request;
  const url = new URL(request.url);
  if (request.method !== 'GET' || url.origin !== self.location.origin || !url.pathname.startsWith(BASE)) return;
  event.respondWith(caches.open(CACHE_NAME).then(async (cache) => {
    // Built assets are fixed files; server CORS negotiation headers do not change them.
    const cached = await cache.match(request, { ignoreSearch: true, ignoreVary: true });
    if (cached) return cached;
    try {
      return await fetch(request);
    } catch (error) {
      if (request.mode === 'navigate') {
        const page = await cache.match(BASE + 'index.html');
        if (page) return page;
      }
      throw error;
    }
  }));
});
`;
}

export function localFirstBuild(options: LocalBuildOptions): Plugin {
  const { base, name, id, description, themeColor = '#eef0ea' } = options;
  if (!base.startsWith('/') || !base.endsWith('/')) throw new Error('Local app base must begin and end with /.');

  return {
    name: 'local-first-build',
    apply: 'build',
    enforce: 'post',
    transformIndexHtml: {
      order: 'pre',
      handler(html) {
        return {
          html: html.replace(/\s*<meta\b(?=[^>]*\bproperty=["']og:url["'])[^>]*>/gi, ''),
          tags: [
            { tag: 'meta', attrs: { 'http-equiv': 'Content-Security-Policy', content: LOCAL_CSP }, injectTo: 'head-prepend' },
            { tag: 'link', attrs: { rel: 'manifest', href: `${base}manifest.webmanifest` }, injectTo: 'head' },
          ],
        };
      },
    },
    generateBundle: {
      order: 'post',
      handler(_outputOptions, bundle) {
        const generated: Record<string, string | Buffer> = {
          'manifest.webmanifest': JSON.stringify({
            id: base,
            name,
            short_name: name,
            description,
            start_url: base,
            scope: base,
            display: 'standalone',
            background_color: themeColor,
            theme_color: themeColor,
            icons: [192, 512].map((size) => ({ src: `${base}icon-${size}.png`, sizes: `${size}x${size}`, type: 'image/png', purpose: 'any maskable' })),
          }, null, 2),
          'icon-192.png': documentIcon(192),
          'icon-512.png': documentIcon(512),
        };
        const digest = createHash('sha256');
        for (const [fileName, asset] of Object.entries(bundle).sort(([left], [right]) => left.localeCompare(right))) {
          digest.update(fileName);
          digest.update(assetBytes(asset));
        }
        for (const [fileName, source] of Object.entries(generated)) {
          digest.update(fileName);
          digest.update(source);
          this.emitFile({ type: 'asset', fileName, source });
        }
        const files = [...new Set([base, ...Object.keys(bundle).map((fileName) => `${base}${fileName}`), ...Object.keys(generated).map((fileName) => `${base}${fileName}`), `${base}sw.js`])].sort();
        const prefix = `${id}-offline-${base.replace(/[^a-zA-Z0-9]/g, '_')}-`;
        digest.update(serviceWorker(prefix, '', base, files));
        const version = digest.digest('hex').slice(0, 16);
        this.emitFile({ type: 'asset', fileName: 'sw.js', source: serviceWorker(prefix, version, base, files) });
      },
    },
  };
}

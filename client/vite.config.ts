import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import { localFirstBuild } from './localBuild';

// "vite build --mode pages" builds the static GitHub Pages demo: it is served
// from /vaultmesh/, uses the in-browser backend and goes to dist-pages so it
// never replaces the build that the server serves.
export default defineConfig(({ mode }) => {
  const pages = mode === 'pages';
  if (pages) process.env.VITE_DEMO_MODE = 'true';
  // loadEnv reads .env / .env.local (see client/.env.example) and lets an
  // actual shell environment variable of the same name override the file,
  // which is what this config itself needs since it runs in Node.
  const env = loadEnv(mode, process.cwd(), '');

  return {
    base: pages ? '/vaultmesh/' : '/',
    plugins: [react(), ...(pages ? [localFirstBuild({ base: '/vaultmesh/', id: 'vaultmesh', name: 'VaultMesh', description: 'An encrypted local notebook for secrets.', themeColor: '#183d32' })] : [])],
    build: {
      outDir: pages ? 'dist-pages' : 'dist',
      assetsInlineLimit: pages ? 0 : undefined,
    },
    define: { 'import.meta.env.VITE_DEMO_MODE': JSON.stringify(pages ? 'true' : 'false') },
    server: {
      port: 3005,
      proxy: {
        '/api': {
          // Override with VITE_API_TARGET (env var or client/.env.local) when
          // the server runs on a non-default port.
          target: env.VITE_API_TARGET || 'http://127.0.0.1:4005',
          changeOrigin: true,
        },
      },
    },
    test: {
      globals: true,
      environment: 'jsdom',
      setupFiles: './src/test/setup.ts',
    },
  };
});

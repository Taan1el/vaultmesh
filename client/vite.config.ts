import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// "vite build --mode pages" builds the static GitHub Pages demo: it is served
// from /vaultmesh/, uses the in-browser backend and goes to dist-pages so it
// never replaces the build that the server serves.
export default defineConfig(({ mode }) => {
  const pages = mode === 'pages';
  if (pages) process.env.VITE_DEMO_MODE = 'true';

  return {
    base: pages ? '/vaultmesh/' : '/',
    plugins: [react()],
    build: {
      outDir: pages ? 'dist-pages' : 'dist',
    },
    server: {
      port: 3005,
      proxy: {
        '/api': {
          // Point the dev proxy at another API port with VITE_API_TARGET=http://127.0.0.1:4100
          target: process.env.VITE_API_TARGET || 'http://127.0.0.1:4005',
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

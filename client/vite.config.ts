import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
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
});

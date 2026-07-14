import { defineConfig } from 'vite';
import preact from '@preact/preset-vite';

export default defineConfig({
  root: 'ui',
  plugins: [preact()],
  build: {
    outDir: '../internal/web/dist',
    emptyOutDir: true,
    sourcemap: false,
    target: 'es2020'
  },
  server: {
    port: 5173,
    strictPort: false,
    proxy: {
      '/api': 'http://127.0.0.1:8787'
    }
  }
});


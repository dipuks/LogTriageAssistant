import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const projectRoot = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  root: resolve(projectRoot, 'client'),
  plugins: [react(), tailwindcss()],
  build: {
    outDir: resolve(projectRoot, 'wwwroot'),
    emptyOutDir: true,
    assetsDir: 'assets',
    sourcemap: false
  }
});

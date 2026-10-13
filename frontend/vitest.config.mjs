import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import { fileURLToPath } from 'node:url';

const config = defineConfig({ root: '.', resolve: { alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) } }, plugins: [react()], test: {
  environment: 'jsdom', include: ['src/**/*.test.ts', 'src/**/*.test.tsx'],
} });
export default config;

import type { Config } from 'tailwindcss';
const config: Config = { content: ['./src/**/*.{js,ts,jsx,tsx,mdx}'], theme: { extend: {
  colors: { wine: '#190917', velvet: '#35102e', rose: '#f04498', gold: '#d6b48c', mist: '#e8dce5' },
  fontFamily: { display: ['var(--font-display)'], sans: ['var(--font-body)'] },
} }, plugins: [] };
export default config;

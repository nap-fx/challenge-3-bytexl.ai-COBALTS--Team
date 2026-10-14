// @ts-check
import { defineConfig } from 'astro/config';
import tailwindcss from '@tailwindcss/vite';

// https://astro.build/config
export default defineConfig({
  site: 'https://nap-fx.github.io',
  base: process.env.GITHUB_PAGES ? '/challenge-3-bytexl.ai-COBALTS--Team' : '/',
  vite: {
    plugins: [tailwindcss()],
  },
});

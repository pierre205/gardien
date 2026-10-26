import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// En dev (npm run dev:ui), Vite sert l'UI et proxifie l'API vers le service
// lancé à côté (npm run demo:api). En démo complète (npm run demo), c'est
// Express qui sert le build : pas de proxy, même origine.
export default defineConfig({
  root: new URL('.', import.meta.url).pathname,
  plugins: [react()],
  build: { outDir: 'dist', emptyOutDir: true },
  server: {
    proxy: {
      '/gardien-api': { target: `http://127.0.0.1:${process.env.GARDIEN_PORT || 8094}` },
    },
  },
})

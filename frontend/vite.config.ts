import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(({ mode }) => {
  // Read env vars from the root .env (same file the backend uses)
  const env = loadEnv(mode, '../');
  const apiTarget = env.VITE_API_URL ?? 'http://localhost:8000';

  return {
    plugins: [react()],
    server: {
      proxy: {
        '/api': {
          target: apiTarget,
          changeOrigin: true,
          rewrite: (path) => path.replace(/^\/api/, ''),
        },
      },
    },
  };
});

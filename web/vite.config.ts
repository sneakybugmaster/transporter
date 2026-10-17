/// <reference types="vitest/config" />
import path from "node:path";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// During `pnpm dev`, API calls are proxied to a coordinator running locally
// (`make run-coordinator`). Override with TRANSPORTER_API=http://host:port.
const api = process.env.TRANSPORTER_API ?? "http://127.0.0.1:8080";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { "@": path.resolve(import.meta.dirname, "src") },
  },
  server: {
    proxy: {
      "/api": api,
      "/healthz": api,
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    // One small admin app embedded in the binary: ~160 kB gzipped is fine.
    chunkSizeWarningLimit: 700,
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test-setup.ts"],
    include: ["src/**/*.test.{ts,tsx}"],
  },
});

import { defineConfig } from "vite";
import { resolve } from "node:path";

export default defineConfig({
  base: "./",
  root: resolve("extension"),
  publicDir: resolve("extension/public"),
  build: {
    outDir: resolve("extension/dist"),
    emptyOutDir: true,
    rollupOptions: {
      input: {
        sidepanel: resolve("extension/sidepanel.html"),
      },
    },
  },
});

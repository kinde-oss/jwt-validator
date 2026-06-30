import { defineConfig } from "vite";
import { resolve } from "path";

export default defineConfig({
  build: {
    copyPublicDir: false,
    lib: {
      entry: resolve(__dirname, "lib/main.ts"),
      formats: ["es", "cjs"],
      name: "@kinde/jwt-validator",
      fileName: "jwt-validator",
    },
    target: "es2020",
    outDir: "dist",
    emptyOutDir: true,
  },
});

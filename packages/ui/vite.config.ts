import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { tanstackRouter } from "@tanstack/router-plugin/vite";

export default defineConfig({
  root: "client",
  appType: "spa",
  server: {
    middlewareMode: true,
  },
  plugins: [
    tanstackRouter({
      target: "react",
      autoCodeSplitting: true,
      routesDirectory: "routes",
      generatedRouteTree: "routeTree.gen.ts",
    }),
    react(),
  ],
  resolve: {
    tsconfigPaths: true,
  },
  build: {
    outDir: "../dist/client",
  },
});

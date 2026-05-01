import { defineConfig } from "oxlint";

export default defineConfig({
  ignorePatterns: ["**/routeTree.gen.ts"],
  categories: {
    correctness: "error",
  },
  plugins: ["typescript", "unicorn", "oxc"],
  env: {
    builtin: true,
  },
});

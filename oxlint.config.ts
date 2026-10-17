import { defineConfig } from "oxlint";

export default defineConfig({
  categories: {
    correctness: "error",
    suspicious: "error",
  },
  plugins: ["typescript", "unicorn", "oxc", "node"],
  env: {
    builtin: true,
    node: true,
  },
  rules: {
    // Terminal code matches ANSI escape sequences on purpose.
    "no-control-regex": "off",
  },
});

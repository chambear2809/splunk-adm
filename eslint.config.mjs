import js from "@eslint/js";
import tseslint from "typescript-eslint";
import reactHooks from "eslint-plugin-react-hooks";
import globals from "globals";
export default tseslint.config(
  { ignores: ["node_modules/**", "dist/**", "research/**", "splunk_app/**"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["frontend/src/**/*.{ts,tsx}", "vite*.ts"],
    languageOptions: { globals: { ...globals.browser, ...globals.node } },
  },
  {
    files: ["frontend/src/**/*.{ts,tsx}", "tests/browser/**/*.{ts,tsx}"],
    plugins: { "react-hooks": reactHooks },
    rules: {
      "react-hooks/rules-of-hooks": "error",
      "react-hooks/exhaustive-deps": "error",
    },
  },
  {
    files: ["tests/browser/**/*.{ts,tsx}", "playwright.config.ts"],
    languageOptions: { globals: { ...globals.browser, ...globals.node } },
  },
  {
    files: ["frontend/src/**/*.test.ts"],
    rules: { "@typescript-eslint/no-explicit-any": "off" },
  },
  {
    files: ["tools/*.mjs", "eslint.config.mjs"],
    languageOptions: { globals: globals.node },
  },
);

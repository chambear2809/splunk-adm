import js from "@eslint/js";
import tseslint from "typescript-eslint";
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
    files: ["tools/*.mjs", "eslint.config.mjs"],
    languageOptions: { globals: globals.node },
  },
);

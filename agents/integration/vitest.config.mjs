import { fileURLToPath } from "node:url";
import path from "node:path";
import { defineConfig } from "vitest/config";

const here = path.dirname(fileURLToPath(import.meta.url));
export default defineConfig({
  root: here,
  resolve: { alias: [
    { find: "@", replacement: path.resolve(here, "../../web") },
    { find: "ajv-formats", replacement: path.join(here, "node_modules/ajv-formats") },
    { find: "ajv", replacement: path.join(here, "node_modules/ajv") },
  ] },
  test: { include: ["backend.test.ts"], fileParallelism: false, testTimeout: 15000, hookTimeout: 20000 },
});

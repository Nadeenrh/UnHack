import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Self-contained server bundle in .next/standalone with only the node_modules files it uses.
  // Dockerfile.prod copies just that, so the image skips dev dependencies and source.
  output: "standalone",
  // No `env:` block on purpose: it would bake DB_HOST/DB_PASSWORD/etc. into the compiled bundle at
  // build time, so secrets would end up in .next/ output and a built server would ignore its runtime settings.
  // Server code reads process.env at runtime. Next.js loads .env.development / .env.production itself.
};

export default nextConfig;

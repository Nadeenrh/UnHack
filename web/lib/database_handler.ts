// The one shared mysql2 pool. NightWatch code goes through lib/nightwatch/db.ts, which wraps it.
import mysql, { Pool } from "mysql2/promise";

// Kept on globalThis, not in a module variable: in `next dev` every hot reload re-runs this
// module, and a module-level pool meant a brand-new pool (up to 10 connections) per edit until
// MySQL answered "Too many connections". One pool per process, however often the code reloads.
const g = globalThis as typeof globalThis & { __nightwatchPool?: Pool | null };

/** Get the pool, creating it on first use from DB_* environment variables (read at runtime). */
export async function getPool(): Promise<Pool> {
  if (g.__nightwatchPool) return g.__nightwatchPool;

  for (const name of [
    "DB_HOST",
    "DB_PORT",
    "DB_USER",
    "DB_PASSWORD",
    "DB_NAME",
  ] as const) {
    if (!process.env[name])
      throw new Error(`Missing required environment variable: ${name}`);
  }

  g.__nightwatchPool = mysql.createPool({
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT),
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: Number(process.env.DB_POOL_SIZE ?? 10),
    queueLimit: 0,
    // Hand idle connections back to MySQL instead of holding all 10 open forever.
    maxIdle: 2,
    idleTimeout: 60_000,
    // NightWatch stores every DATETIME in UTC. Without this, mysql2 converts using the
    // machine's local time zone, so a Toronto laptop would shift every timestamp by hours.
    timezone: "Z",
  });
  return g.__nightwatchPool;
}

/** Close the pool (tests and graceful shutdown). */
export async function closePool(): Promise<void> {
  const p = g.__nightwatchPool;
  if (p) {
    g.__nightwatchPool = null;
    await p.end();
  }
}

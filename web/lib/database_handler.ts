// The one shared mysql2 pool. Nightwatch code goes through lib/nightwatch/db.ts, which wraps it.
import mysql, { Pool } from "mysql2/promise";

let pool: Pool | null = null;

/** Get the pool, creating it on first use from DB_* environment variables (read at runtime). */
export async function getPool(): Promise<Pool> {
  if (pool) return pool;

  for (const name of ["DB_HOST", "DB_PORT", "DB_USER", "DB_PASSWORD", "DB_NAME"] as const) {
    if (!process.env[name]) throw new Error(`Missing required environment variable: ${name}`);
  }

  pool = mysql.createPool({
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT),
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: Number(process.env.DB_POOL_SIZE ?? 10),
    queueLimit: 0,
    // Nightwatch stores every DATETIME in UTC. Without this, mysql2 converts using the
    // machine's local time zone, so a Toronto laptop would shift every timestamp by hours.
    timezone: "Z",
  });
  return pool;
}

/** Close the pool (tests and graceful shutdown). */
export async function closePool(): Promise<void> {
  if (pool) {
    const p = pool;
    pool = null;
    await p.end();
  }
}

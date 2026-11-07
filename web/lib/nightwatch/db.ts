// Small typed layer over the shared mysql2 pool (lib/database_handler.ts).
// Every Nightwatch query goes through here, always with ? placeholders, never string-built values.

import type { PoolConnection, ResultSetHeader, RowDataPacket } from "mysql2/promise";
import { getPool } from "@/lib/database_handler";

export type Param = string | number | boolean | Date | null;
export type Executor = Pick<PoolConnection, "execute" | "query">;

async function runner(conn?: Executor): Promise<Executor> {
  return conn ?? (await getPool());
}

export async function rows<T>(sql: string, params: Param[] = [], conn?: Executor): Promise<T[]> {
  const [result] = await (await runner(conn)).execute<RowDataPacket[]>(sql, params);
  return result as unknown as T[];
}

export async function one<T>(sql: string, params: Param[] = [], conn?: Executor): Promise<T | null> {
  const result = await rows<T>(sql, params, conn);
  return result[0] ?? null;
}

export async function exec(sql: string, params: Param[] = [], conn?: Executor): Promise<ResultSetHeader> {
  const [result] = await (await runner(conn)).execute<ResultSetHeader>(sql, params);
  return result;
}

/** Run fn in one transaction: commit on success, roll back on any error. */
export async function tx<T>(fn: (conn: PoolConnection) => Promise<T>): Promise<T> {
  const pool = await getPool();
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const out = await fn(conn);
    await conn.commit();
    return out;
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}

/** `?, ?, ?` for an IN (...) list. Never call with an empty array. */
export function placeholders(n: number): string {
  if (n < 1) throw new Error("placeholders() needs at least one value");
  return new Array(n).fill("?").join(", ");
}

/** mysql2 returns DATETIME as Date (UTC, see pool timezone). Contract wants ISO strings. */
export function iso(value: Date | string | null | undefined): string | null {
  if (value === null || value === undefined) return null;
  const d = value instanceof Date ? value : new Date(value);
  return d.toISOString();
}

/** Same as iso() for columns that are NOT NULL. */
export function isoRequired(value: Date | string): string {
  return iso(value) as string;
}

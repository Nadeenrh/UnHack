// Integration-test harness: loads the real schema + fixtures into a throwaway database
// and builds requests the way a browser would (cookie, Origin, Host).
//
// Run:  NW_TEST_DB=1 DB_HOST=127.0.0.1 DB_PORT=3307 DB_USER=root DB_PASSWORD=... npx vitest run tests/nightwatch
// Uses database `nightwatch_test`, which it drops and recreates. Never point it at real data.

import { readFileSync } from "node:fs";
import path from "node:path";
import mysql from "mysql2/promise";
import { NextRequest } from "next/server";
import { closePool } from "@/lib/database_handler";
import { resetThrottleForTests } from "@/lib/nightwatch/auth";

export const TEST_DB = "nightwatch_test";
export const enabled = process.env.NW_TEST_DB === "1";
export const DEV_PASSWORD = "pass123";

const ROOT = path.resolve(__dirname, "../..");

/** Split a .sql file into statements, honouring the mysql client's DELIMITER command. */
export function splitSql(sql: string): string[] {
  const out: string[] = [];
  let delimiter = ";";
  let buf: string[] = [];
  for (const line of sql.split(/\r?\n/)) {
    const trimmed = line.trim();
    const m = /^DELIMITER\s+(\S+)/i.exec(trimmed);
    if (m) {
      delimiter = m[1];
      continue;
    }
    if (!buf.length && (trimmed === "" || trimmed.startsWith("--"))) continue;
    buf.push(line);
    if (trimmed.endsWith(delimiter)) {
      const stmt = buf.join("\n").trim();
      out.push(stmt.slice(0, stmt.length - delimiter.length).trim());
      buf = [];
    }
  }
  if (buf.join("").trim()) out.push(buf.join("\n").trim());
  return out.filter(Boolean);
}

function loadFile(rel: string): string {
  return readFileSync(path.join(ROOT, rel), "utf8")
    .replace(/CREATE DATABASE IF NOT EXISTS nightwatch\b/, `CREATE DATABASE IF NOT EXISTS ${TEST_DB}`)
    .replace(/USE nightwatch;/g, `USE ${TEST_DB};`);
}

export async function resetDatabase({ fixtures = true } = {}): Promise<void> {
  await closePool();
  resetThrottleForTests();
  process.env.DB_NAME = TEST_DB;
  const conn = await mysql.createConnection({
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT),
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    timezone: "Z",
  });
  try {
    await conn.query(`DROP DATABASE IF EXISTS ${TEST_DB}`);
    const files = ["db/nightwatch/init/001_schema.sql"];
    if (fixtures) files.push("db/nightwatch/init/002_dev_fixtures.sql");
    for (const f of files) for (const stmt of splitSql(loadFile(f))) await conn.query(stmt);
  } finally {
    await conn.end();
  }
}

export async function teardown(): Promise<void> {
  await closePool();
}

// ---- requests -------------------------------------------------------------

export function req(
  method: string,
  url: string,
  { body, cookie, origin = "http://localhost", headers = {} }: {
    body?: unknown;
    cookie?: string;
    origin?: string | null;
    headers?: Record<string, string>;
  } = {}
): NextRequest {
  const h = new Headers({ host: "localhost", ...headers });
  if (origin) h.set("origin", origin);
  if (cookie) h.set("cookie", cookie);
  if (body !== undefined) h.set("content-type", "application/json");
  return new NextRequest(`http://localhost${url}`, {
    method,
    headers: h,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

/** Route handler context with Next 16's promised params. */
export function ctx<P extends Record<string, string>>(params: P = {} as P) {
  return { params: Promise.resolve(params) };
}

/** Pull "nw_session=..." out of a response so the next request can send it. */
export function sessionCookie(res: Response): string {
  const set = res.headers.get("set-cookie") ?? "";
  const m = /nw_session=([^;]*)/.exec(set);
  if (!m || !m[1]) throw new Error(`no session cookie in response (status ${res.status})`);
  return `nw_session=${m[1]}`;
}

export async function body<T = any>(res: Response): Promise<T> {
  return (await res.json()) as T;
}

/** Sign in as a fixture user and return their cookie. */
export async function signIn(email: string, password = DEV_PASSWORD): Promise<string> {
  const { POST } = await import("@/app/api/v1/auth/login/route");
  const res = await POST(req("POST", "/api/v1/auth/login", { body: { email, password } }), ctx());
  return sessionCookie(res);
}

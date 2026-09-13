import { getEnv } from "./config/env.js";
import type { LogLevel } from "./types.js";

type LogFn = (msg: string, meta?: Record<string, unknown>) => void;

export interface Logger {
  trace: LogFn;
  debug: LogFn;
  info: LogFn;
  warn: LogFn;
  error: LogFn;
  fatal: LogFn;
  child: (bindings: Record<string, unknown>) => Logger;
}

const LEVELS: Record<LogLevel | "trace" | "debug" | "info" | "warn" | "error" | "fatal", number> = {
  trace: 10,
  debug: 20,
  info: 30,
  warn: 40,
  error: 50,
  fatal: 60,
};

const COLORS: Record<string, string> = {
  trace: "\x1b[90m",
  debug: "\x1b[36m",
  info: "\x1b[32m",
  warn: "\x1b[33m",
  error: "\x1b[31m",
  fatal: "\x1b[41m\x1b[37m",
};
const RESET = "\x1b[0m";

/**
 * Keys whose values must never reach a log sink (S06): credentials, tokens,
 * signatures and session material. Matching is case-insensitive on the key
 * name; the value is replaced, whatever its type.
 */
const SENSITIVE_KEY =
  /(token|secret|password|passwd|authorization|cookie|credential|signature|api[_-]?key|private[_-]?key|session)/i;

/** Recursively replace the values of sensitive keys with `[REDACTED]`. */
export function redactSensitive<T>(value: T, depth = 0): T {
  if (value === null || typeof value !== "object" || depth > 6) return value;
  if (Array.isArray(value)) return value.map((v) => redactSensitive(v, depth + 1)) as unknown as T;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    out[k] = SENSITIVE_KEY.test(k) ? "[REDACTED]" : redactSensitive(v, depth + 1);
  }
  return out as unknown as T;
}

/**
 * Minimal structured logger (JSON in production, human-readable in dev).
 * Swappable — Fastify/pino can replace this without touching call sites.
 */
export function createLogger(bindings: Record<string, unknown> = {}): Logger {
  let levelName: LogLevel = "info";
  try {
    levelName = getEnv().LOG_LEVEL;
  } catch {
    /* ignore */
  }
  const threshold = LEVELS[levelName] ?? LEVELS.info;

  function write(level: keyof typeof LEVELS, msg: string, meta?: Record<string, unknown>) {
    if (LEVELS[level] < threshold) return;
    const ts = new Date().toISOString();
    const all = redactSensitive({ ...bindings, ...(meta ?? {}) });
    const isProd = process.env.NODE_ENV === "production";
    const line = isProd
      ? JSON.stringify({ ts, level, msg, ...all })
      : `${COLORS[level] ?? ""}[${ts}] ${level.toUpperCase().padEnd(5)}${RESET} ${msg} ${
          Object.keys(all).length ? JSON.stringify(all) : ""
        }`;

    (level === "error" || level === "fatal" ? console.error : console.log)(line);
  }

  return {
    trace: (m, meta) => write("trace", m, meta),
    debug: (m, meta) => write("debug", m, meta),
    info: (m, meta) => write("info", m, meta),
    warn: (m, meta) => write("warn", m, meta),
    error: (m, meta) => write("error", m, meta),
    fatal: (m, meta) => write("fatal", m, meta),
    child: (b) => createLogger({ ...bindings, ...b }),
  };
}

export const logger = createLogger({ component: "app" });

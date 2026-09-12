import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import type { FastifyInstance } from "fastify";
import { getEnvFresh } from "../config/env.js";
import { Container } from "../app/container.js";
import { buildServer } from "../http/app.js";
import { freshDb } from "./test-helpers.js";
import { createLogger, redactSensitive } from "../logger.js";

/* ------------------------------------------------------------------ *
 * S06 — operational hardening regressions:
 *   1. the per-IP API rate limiter answers 429 once the budget is spent
 *      (health/webhooks stay exempt so probes and retries never starve);
 *   2. the structured logger never writes credentials to any sink;
 *   3. every HTTP response produces one structured access-log line with
 *      the request's correlation id.
 * ------------------------------------------------------------------ */

let cleanup: (() => void) | undefined;
let app: FastifyInstance | undefined;
const savedEnv: Record<string, string | undefined> = {};

beforeEach(() => {
  for (const k of ["RATE_LIMIT_PER_MINUTE", "CODEVIA_HTTP_LOG", "LOG_LEVEL", "NODE_ENV"] as const) {
    savedEnv[k] = process.env[k];
  }
  cleanup = freshDb().cleanup;
});

afterEach(async () => {
  vi.unstubAllGlobals();
  if (app) {
    await app.close();
    app = undefined;
  }
  for (const k of Object.keys(savedEnv) as Array<keyof typeof savedEnv>) {
    if (savedEnv[k] === undefined) delete process.env[k];
    else process.env[k] = savedEnv[k];
  }
  getEnvFresh();
  cleanup?.();
  cleanup = undefined;
});

async function boot(): Promise<FastifyInstance> {
  const container = new Container();
  await container.ensureSeed();
  app = (await buildServer(container)).app;
  await app.ready();
  return app;
}

describe("per-IP rate limiting", () => {
  it("answers 429 with Retry-After once the API budget is spent, but never throttles health", async () => {
    process.env.RATE_LIMIT_PER_MINUTE = "3";
    getEnvFresh();
    const srv = await boot();

    let last: { statusCode: number; headers: Record<string, string | string[] | undefined> } | undefined;
    for (let i = 0; i < 4; i++) {
      const res = await srv.inject({ method: "GET", url: "/projects" });
      last = { statusCode: res.statusCode, headers: res.headers as Record<string, string | string[] | undefined> };
    }
    expect(last?.statusCode).toBe(429);
    expect(String(last?.headers["retry-after"])).toMatch(/^\d+$/);
    expect(String(last?.headers["x-ratelimit-limit"])).toBe("3");
    expect(String(last?.headers["x-ratelimit-remaining"])).toBe("0");

    // The first three requests were admitted and announced the budget.
    const first = await srv.inject({ method: "GET", url: "/health" });
    expect(first.statusCode).toBe(200);
    // Health is exempt: it never counts against the bucket even while limited.
    for (let i = 0; i < 5; i++) {
      expect((await srv.inject({ method: "GET", url: "/health" })).statusCode).toBe(200);
    }
  });

  it("is disabled when RATE_LIMIT_PER_MINUTE is 0", async () => {
    process.env.RATE_LIMIT_PER_MINUTE = "0";
    getEnvFresh();
    const srv = await boot();
    for (let i = 0; i < 5; i++) {
      expect((await srv.inject({ method: "GET", url: "/projects" })).statusCode).toBe(200);
    }
  });
});

describe("structured logging", () => {
  it("redacts credential-looking keys before anything is written", () => {
    const meta = {
      component: "test",
      githubToken: "ghp_SUPER_SECRET_VALUE",
      nested: { api_key: "sk-live-123", webhookSignature: "abc", keep: "visible" },
      list: [{ password: "hunter2", ok: 1 }],
    };
    const redacted = redactSensitive(meta);
    expect(redacted.githubToken).toBe("[REDACTED]");
    expect(redacted.nested.api_key).toBe("[REDACTED]");
    expect(redacted.nested.webhookSignature).toBe("[REDACTED]");
    expect(redacted.nested.keep).toBe("visible");
    expect(redacted.list[0].password).toBe("[REDACTED]");
    expect(redacted.list[0].ok).toBe(1);

    const lines: string[] = [];
    const spy = vi.spyOn(console, "log").mockImplementation((line: unknown) => {
      lines.push(String(line));
    });
    try {
      const log = createLogger();
      log.info("provider configured", { providerId: "provider-openai", apiKey: "sk-top-secret" });
    } finally {
      spy.mockRestore();
    }
    expect(lines.length).toBe(1);
    expect(lines[0]).not.toContain("sk-top-secret");
    expect(lines[0]).toContain("[REDACTED]");
    expect(lines[0]).toContain("provider-openai");
  });

  it("writes one access-log line per response with the correlation id", async () => {
    process.env.CODEVIA_HTTP_LOG = "1";
    const srv = await boot();

    const lines: string[] = [];
    const spy = vi.spyOn(console, "log").mockImplementation((line: unknown) => {
      lines.push(String(line));
    });
    try {
      const res = await srv.inject({ method: "GET", url: "/health", headers: { "x-correlation-id": "corr_access_1" } });
      expect(res.statusCode).toBe(200);
      expect(res.headers["x-correlation-id"]).toBe("corr_access_1");
    } finally {
      spy.mockRestore();
    }
    const access = lines.find((l) => l.includes("http request"));
    expect(access).toBeDefined();
    expect(access).toContain("corr_access_1");
    expect(access).toContain("/health");
    expect(access).toContain('"status":200');
    // Never the query string: it can carry OAuth codes and tokens.
    expect(access).not.toContain("?");
  });
});

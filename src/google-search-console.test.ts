import { afterEach, describe, expect, test } from "bun:test";
import * as searchConsole from "./client.ts";
import {
  assertAllowedFlags,
  assertOnboardingConfirmation,
  clicksSummary,
  parseArgs,
  propertySummary,
  usage,
} from "./cli.ts";

const TOKEN_URI = "https://oauth2.example.test/token";
const CLIENT_ID = "fixture-client-id";
const CLIENT_SECRET = "fixture-client-secret-value";
const REFRESH_TOKEN = "fixture-refresh-token-value";
const ACCESS_TOKEN = "fixture-access-token-value";
const property = {
  siteUrl: "https://www.example.com/",
  permissionLevel: "siteOwner",
};

const environment = [
  "GOOGLE_SEARCH_CONSOLE_CLIENT_ID",
  "GOOGLE_SEARCH_CONSOLE_CLIENT_SECRET",
  "GOOGLE_SEARCH_CONSOLE_REFRESH_TOKEN",
  "GOOGLE_SEARCH_CONSOLE_TOKEN_URI",
] as const;

const previousEnvironment = new Map<string, string | undefined>();
let previousFetch: typeof fetch;

function useCredentials(): void {
  for (const name of environment) previousEnvironment.set(name, process.env[name]);
  process.env.GOOGLE_SEARCH_CONSOLE_CLIENT_ID = CLIENT_ID;
  process.env.GOOGLE_SEARCH_CONSOLE_CLIENT_SECRET = CLIENT_SECRET;
  process.env.GOOGLE_SEARCH_CONSOLE_REFRESH_TOKEN = REFRESH_TOKEN;
  process.env.GOOGLE_SEARCH_CONSOLE_TOKEN_URI = TOKEN_URI;
}

function tokenResponse(): Response {
  return new Response(
    JSON.stringify({ access_token: ACCESS_TOKEN, expires_in: 3600 }),
    { status: 200, headers: { "Content-Type": "application/json" } },
  );
}

function apiResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

afterEach(() => {
  globalThis.fetch = previousFetch;
  for (const name of environment) {
    const value = previousEnvironment.get(name);
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
  previousEnvironment.clear();
  searchConsole.resetForTests();
});

describe("Google Search Console client with mocked OAuth/API", () => {
  test("refreshes OAuth, lists properties, verifies exactly, and queries aggregate clicks", async () => {
    previousFetch = globalThis.fetch;
    useCredentials();
    searchConsole.resetForTests();
    const requests: { method: string; url: string; init?: RequestInit }[] = [];

    globalThis.fetch = (async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method || "GET";
      requests.push({ method, url, init });
      if (url === TOKEN_URI) {
        const form = new URLSearchParams(String(init?.body));
        expect(form.get("client_id")).toBe(CLIENT_ID);
        expect(form.get("client_secret")).toBe(CLIENT_SECRET);
        expect(form.get("refresh_token")).toBe(REFRESH_TOKEN);
        expect(form.get("grant_type")).toBe("refresh_token");
        return tokenResponse();
      }
      const parsed = new URL(url);
      expect(init?.headers).toMatchObject({ Authorization: `Bearer ${ACCESS_TOKEN}` });
      if (parsed.pathname === "/webmasters/v3/sites") {
        return apiResponse({ siteEntry: [property] });
      }
      if (parsed.pathname === "/webmasters/v3/sites/https%3A%2F%2Fwww.example.com%2F/searchAnalytics/query") {
        const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
        expect(body).toEqual({
          startDate: "2026-09-01",
          endDate: "2026-09-03",
          type: "web",
          aggregationType: "auto",
        });
        expect(body).not.toHaveProperty("dimensions");
        return apiResponse({ rows: [{ clicks: 12.5, impressions: 99, keys: ["must-not-escape"] }] });
      }
      return apiResponse({ error: { message: "not found" } }, 404);
    }) as unknown as typeof fetch;

    await expect(searchConsole.listProperties()).resolves.toEqual([property]);
    await expect(searchConsole.verifyProperty("https://www.example.com/")).resolves.toEqual({
      ...property,
      verified: true,
    });
    await expect(searchConsole.queryClicks(property.siteUrl, 3, "2026-09-03")).resolves.toEqual({
      totalClicks: 12.5,
      startDate: "2026-09-01",
      endDate: "2026-09-03",
      sourceHealthy: true,
    });
    expect(requests.filter((request) => request.url === TOKEN_URI)).toHaveLength(1);
    expect(requests.filter((request) => request.url.includes("searchAnalytics/query"))).toHaveLength(1);
  });

  test("treats an empty successful result as zero while marking the source healthy", async () => {
    previousFetch = globalThis.fetch;
    useCredentials();
    globalThis.fetch = (async (input: string | URL) => {
      if (String(input) === TOKEN_URI) return tokenResponse();
      return apiResponse({ rows: [] });
    }) as unknown as typeof fetch;

    await expect(searchConsole.queryClicks(property.siteUrl, 1, "2026-09-03")).resolves.toEqual({
      totalClicks: 0,
      startDate: "2026-09-03",
      endDate: "2026-09-03",
      sourceHealthy: true,
    });
  });

  test("does not fuzzy-match an inaccessible property", async () => {
    previousFetch = globalThis.fetch;
    useCredentials();
    globalThis.fetch = (async (input: string | URL) => {
      if (String(input) === TOKEN_URI) return tokenResponse();
      return apiResponse({ siteEntry: [{ siteUrl: "https://example.com/", permissionLevel: "siteOwner" }] });
    }) as unknown as typeof fetch;

    await expect(searchConsole.verifyProperty("https://www.example.com/")).rejects.toThrow(
      "property not found or not accessible",
    );
  });

  test("turns an insufficient-scope response into an actionable safe error", async () => {
    previousFetch = globalThis.fetch;
    useCredentials();
    globalThis.fetch = (async (input: string | URL) => {
      if (String(input) === TOKEN_URI) return tokenResponse();
      return apiResponse({
        error: {
          code: 403,
          message: "Request had insufficient authentication scopes.",
          errors: [{ reason: "insufficientPermissions", message: "fixture-provider-detail" }],
        },
      }, 403);
    }) as unknown as typeof fetch;

    const error = await searchConsole.listProperties().catch((value: unknown) => value);
    expect(error).toBeInstanceOf(Error);
    const message = String(error);
    expect(message).toContain("webmasters.readonly");
    expect(message).not.toContain("fixture-provider-detail");
  });

  test("surfaces stale OAuth/API errors and never converts them into zero", async () => {
    previousFetch = globalThis.fetch;
    useCredentials();
    globalThis.fetch = (async (input: string | URL) => {
      if (String(input) === TOKEN_URI) return tokenResponse();
      return apiResponse({ error: { message: "expired grant" } }, 401);
    }) as unknown as typeof fetch;

    await expect(searchConsole.listProperties()).rejects.toThrow("authentication failed");
    expect(() => searchConsole.dateRange(0)).toThrow("1 to 365");
    expect(() => searchConsole.dateRange(366)).toThrow("1 to 365");
    expect(() => searchConsole.dateRange(2, "2026-02-30")).toThrow("real calendar date");
  });

  test("rejects malformed rows instead of treating them as zero", async () => {
    previousFetch = globalThis.fetch;
    useCredentials();
    globalThis.fetch = (async (input: string | URL) => {
      if (String(input) === TOKEN_URI) return tokenResponse();
      return apiResponse({ rows: [{ clicks: "12" }] });
    }) as unknown as typeof fetch;

    await expect(searchConsole.queryClicks(property.siteUrl, 1, "2026-09-03")).rejects.toThrow("malformed");
  });

  test("fails clearly when credentials were not provided", async () => {
    previousFetch = globalThis.fetch;
    for (const name of environment) delete process.env[name];
    await expect(searchConsole.listProperties()).rejects.toThrow("Provide them through the process environment");
  });
});

describe("Google Search Console CLI contract", () => {
  test("parses the documented range flags and rejects duplicates/unknown flags", () => {
    expect(parseArgs(["clicks", "https://www.example.com/", "--days", "90", "--end-date", "2026-09-03", "--json"])).toEqual({
      positional: ["clicks", "https://www.example.com/"],
      flags: { days: "90", "end-date": "2026-09-03", json: true },
    });
    expect(() => parseArgs(["clicks", "property", "--days"])).toThrow("requires a value");
    expect(() => parseArgs(["clicks", "property", "--json", "--json"])).toThrow("duplicate flag");
    expect(() => assertAllowedFlags("properties", { days: "90" })).toThrow("unknown flag");
    expect(usage()).not.toContain("--query");
    expect(usage()).not.toContain("--page");
  });

  test("parses the explicit OAuth onboarding flags", () => {
    expect(parseArgs([
      "onboard",
      "--confirm",
      "--port",
      "43817",
      "--redirect-uri",
      "http://localhost:8888/callback",
      "--timeout-seconds",
      "300",
      "--no-browser",
    ])).toEqual({
      positional: ["onboard"],
      flags: {
        confirm: true,
        port: "43817",
        "redirect-uri": "http://localhost:8888/callback",
        "timeout-seconds": "300",
        "no-browser": true,
      },
    });
    expect(() => assertAllowedFlags("onboard", { json: true })).toThrow("unknown flag");
    expect(() => assertOnboardingConfirmation({})).toThrow("--confirm");
    expect(() => assertOnboardingConfirmation({ confirm: true })).not.toThrow();
    expect(usage()).toContain("GOOGLE_SEARCH_CONSOLE_CREDENTIAL_COMMAND");
    expect(usage()).toContain("--confirm");
    expect(usage()).toContain("--redirect-uri URI");
    expect(() => assertAllowedFlags("onboard", { "redirect-uri": "http://localhost:8888/callback" })).not.toThrow();
  });

  test("projects only safe property and aggregate fields", () => {
    const safeProperty = propertySummary(property);
    const safeClicks = clicksSummary(property, {
      totalClicks: 4,
      startDate: "2026-09-01",
      endDate: "2026-09-03",
      sourceHealthy: true,
    });
    expect(safeProperty).toEqual({ property: property.siteUrl, permission: property.permissionLevel });
    expect(safeClicks).toEqual({
      property: property.siteUrl,
      permission: property.permissionLevel,
      totalClicks: 4,
      startDate: "2026-09-01",
      endDate: "2026-09-03",
      sourceHealthy: true,
    });
    expect(JSON.stringify(safeClicks)).not.toContain("keys");
    expect(JSON.stringify(safeClicks)).not.toContain("impressions");
  });
});

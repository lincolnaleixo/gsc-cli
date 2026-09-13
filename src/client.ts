import type {
  SearchConsoleApiError,
  SearchConsoleClicks,
  SearchConsoleProperty,
  VerifiedSearchConsoleProperty,
} from "./types.ts";

const API_BASE = "https://www.googleapis.com/webmasters/v3";
const DEFAULT_TOKEN_URI = "https://oauth2.googleapis.com/token";

interface SearchConsoleConfig {
  clientId: string;
  clientSecret: string;
  refreshToken: string;
  tokenUri: string;
}

interface TokenCache {
  accessToken: string;
  expiresAt: number;
}

interface DateRange {
  startDate: string;
  endDate: string;
}

let tokenCache: TokenCache | null = null;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function configuredValues(): string[] {
  return [
    process.env.GOOGLE_SEARCH_CONSOLE_CLIENT_ID,
    process.env.GOOGLE_SEARCH_CONSOLE_CLIENT_SECRET,
    process.env.GOOGLE_SEARCH_CONSOLE_REFRESH_TOKEN,
    process.env.GOOGLE_SEARCH_CONSOLE_TOKEN_URI,
  ].filter((value): value is string => Boolean(value));
}

function redact(value: string): string {
  let safe = value;
  for (const secret of configuredValues()) {
    if (secret.length >= 3) safe = safe.split(secret).join("[redacted]");
  }
  return safe
    .replace(/Bearer\s+[^\s"']+/gi, "Bearer [redacted]")
    .replace(/(access_token|refresh_token|client_secret)=([^&\s]+)/gi, "$1=[redacted]");
}

function config(): SearchConsoleConfig {
  const names = {
    clientId: "GOOGLE_SEARCH_CONSOLE_CLIENT_ID",
    clientSecret: "GOOGLE_SEARCH_CONSOLE_CLIENT_SECRET",
    refreshToken: "GOOGLE_SEARCH_CONSOLE_REFRESH_TOKEN",
  } as const;
  const missing = Object.values(names).filter((name) => !process.env[name]?.trim());
  if (missing.length > 0) {
    throw new Error(
      `Google Search Console credentials missing: ${missing.join(", ")}. ` +
        "Run through `system-vault run google-search-console --`.",
    );
  }

  const tokenUri = process.env.GOOGLE_SEARCH_CONSOLE_TOKEN_URI?.trim() || DEFAULT_TOKEN_URI;
  if (!/^https:\/\//i.test(tokenUri)) {
    throw new Error("GOOGLE_SEARCH_CONSOLE_TOKEN_URI must use HTTPS.");
  }

  return {
    clientId: process.env[names.clientId]!.trim(),
    clientSecret: process.env[names.clientSecret]!.trim(),
    refreshToken: process.env[names.refreshToken]!.trim(),
    tokenUri,
  };
}

async function parseJson(response: Response): Promise<unknown> {
  const raw = await response.text();
  if (!raw.trim()) return null;
  try {
    return JSON.parse(raw) as unknown;
  } catch {
    throw new Error(`Google Search Console API returned malformed JSON (HTTP ${response.status}).`);
  }
}

function tokenFailure(response: Response, payload: unknown): Error {
  const body = isRecord(payload) ? payload : {};
  const code = nonEmptyString(body.error) ? body.error : `HTTP ${response.status}`;
  const detail = nonEmptyString(body.error_description) ? `: ${redact(body.error_description)}` : "";
  return new Error(`Google Search Console token refresh failed (${redact(code)})${detail}.`);
}

async function getAccessToken(): Promise<string> {
  if (tokenCache && Date.now() < tokenCache.expiresAt - 60_000) return tokenCache.accessToken;

  const current = config();
  const body = new URLSearchParams({
    client_id: current.clientId,
    client_secret: current.clientSecret,
    refresh_token: current.refreshToken,
    grant_type: "refresh_token",
  });

  let response: Response;
  try {
    response = await fetch(current.tokenUri, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    });
  } catch (error) {
    const detail = error instanceof Error ? redact(error.message) : "request failed";
    throw new Error(`Google Search Console token refresh request failed: ${detail}`);
  }

  let payload: unknown;
  try {
    payload = await parseJson(response);
  } catch {
    throw new Error(`Google Search Console token refresh returned malformed JSON (HTTP ${response.status}).`);
  }
  if (!response.ok) throw tokenFailure(response, payload);
  if (!isRecord(payload) || !nonEmptyString(payload.access_token)) {
    throw new Error("Google Search Console token refresh returned no access token.");
  }

  const expiresIn = typeof payload.expires_in === "number" && Number.isFinite(payload.expires_in)
    ? payload.expires_in
    : 3600;
  if (expiresIn <= 0) throw new Error("Google Search Console token refresh returned an invalid expiry.");

  tokenCache = {
    accessToken: payload.access_token.trim(),
    expiresAt: Date.now() + expiresIn * 1000,
  };
  return tokenCache.accessToken;
}

function apiError(response: Response, payload: unknown): Error {
  const error = isRecord(payload) && isRecord(payload.error) ? payload.error as SearchConsoleApiError : {};
  const message = nonEmptyString(error.message) ? error.message.toLowerCase() : "";
  const reasons = Array.isArray(error.errors)
    ? error.errors
        .map((entry) => (isRecord(entry) && nonEmptyString(entry.reason) ? entry.reason.toLowerCase() : ""))
        .filter(Boolean)
    : [];
  const insufficientScope =
    (message.includes("insufficient") && message.includes("scope")) ||
    reasons.some((reason) => reason.includes("insufficient") || reason.includes("scope"));

  if (insufficientScope) {
    return new Error(
      "Google Search Console API rejected the request because the OAuth profile lacks the required " +
        "webmasters.readonly scope; reauthorize the dedicated Vault profile.",
    );
  }
  if (response.status === 401) {
    return new Error("Google Search Console API authentication failed; the OAuth profile may be stale.");
  }
  if (response.status === 403) {
    return new Error("Google Search Console API access denied for this account or property.");
  }
  if (response.status === 404) {
    return new Error("Google Search Console property was not found or is not accessible.");
  }
  return new Error(`Google Search Console API request failed (HTTP ${response.status}).`);
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const accessToken = await getAccessToken();
  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      ...init,
      headers: {
        Accept: "application/json",
        ...(init?.body === undefined ? {} : { "Content-Type": "application/json" }),
        ...(init?.headers ?? {}),
        Authorization: `Bearer ${accessToken}`,
      },
    });
  } catch (error) {
    const detail = error instanceof Error ? redact(error.message) : "request failed";
    throw new Error(`Google Search Console API request failed: ${detail}`);
  }

  let payload: unknown;
  try {
    payload = await parseJson(response);
  } catch {
    throw new Error(`Google Search Console API returned malformed JSON (HTTP ${response.status}).`);
  }
  if (!response.ok) throw apiError(response, payload);
  return payload as T;
}

function parseProperties(payload: unknown): SearchConsoleProperty[] {
  if (!isRecord(payload)) throw new Error("Google Search Console properties response was malformed.");
  const entries = payload.siteEntry;
  if (entries === undefined) return [];
  if (!Array.isArray(entries)) throw new Error("Google Search Console properties response was malformed.");

  return entries.map((entry, index) => {
    if (!isRecord(entry) || !nonEmptyString(entry.siteUrl) || !nonEmptyString(entry.permissionLevel)) {
      throw new Error(`Google Search Console properties response was malformed at entry ${index}.`);
    }
    return {
      siteUrl: entry.siteUrl.trim(),
      permissionLevel: entry.permissionLevel.trim(),
    };
  }).sort((left, right) => left.siteUrl.localeCompare(right.siteUrl));
}

function parseDate(value: string, label: string): string {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) throw new Error(`${label} must use YYYY-MM-DD.`);
  const timestamp = Date.parse(`${value}T00:00:00Z`);
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString().slice(0, 10) !== value) {
    throw new Error(`${label} must be a real calendar date.`);
  }
  return value;
}

export function dateRange(days: number, endDate?: string): DateRange {
  if (!Number.isInteger(days) || days < 1 || days > 365) {
    throw new Error("days must be an integer from 1 to 365.");
  }
  const end = parseDate(endDate ?? new Date().toISOString().slice(0, 10), "end-date");
  const endTimestamp = Date.parse(`${end}T00:00:00Z`);
  const start = new Date(endTimestamp - (days - 1) * 86_400_000).toISOString().slice(0, 10);
  return { startDate: start, endDate: end };
}

function propertyInput(property: string): string {
  const value = property.trim();
  if (!value) throw new Error("property is required.");
  if (/[\r\n]/.test(value)) throw new Error("property cannot contain line breaks.");
  return value;
}

function parseClicks(payload: unknown, range: DateRange): SearchConsoleClicks {
  if (!isRecord(payload)) throw new Error("Google Search Console clicks response was malformed.");
  const rows = payload.rows;
  if (rows !== undefined && !Array.isArray(rows)) {
    throw new Error("Google Search Console clicks response was malformed.");
  }

  let totalClicks = 0;
  for (const [index, row] of (rows ?? []).entries()) {
    if (!isRecord(row) || typeof row.clicks !== "number" || !Number.isFinite(row.clicks) || row.clicks < 0) {
      throw new Error(`Google Search Console clicks response was malformed at row ${index}.`);
    }
    totalClicks += row.clicks;
  }
  if (!Number.isFinite(totalClicks)) throw new Error("Google Search Console clicks total was invalid.");
  return { totalClicks, ...range, sourceHealthy: true };
}

/** List properties visible to the dedicated Search Console OAuth account. */
export async function listProperties(): Promise<SearchConsoleProperty[]> {
  return parseProperties(await request<unknown>("/sites"));
}

/** Confirm one exact property string; never perform a partial or fuzzy match. */
export async function verifyProperty(property: string): Promise<VerifiedSearchConsoleProperty> {
  const requested = propertyInput(property);
  const found = (await listProperties()).find((entry) => entry.siteUrl === requested);
  if (!found) throw new Error(`Google Search Console property not found or not accessible: ${requested}`);
  return { ...found, verified: true };
}

/** Query aggregate web clicks for an inclusive date range without any dimensions. */
export async function queryClicks(
  property: string,
  days: number,
  endDate?: string,
): Promise<SearchConsoleClicks> {
  const requested = propertyInput(property);
  const range = dateRange(days, endDate);
  const payload = {
    startDate: range.startDate,
    endDate: range.endDate,
    type: "web",
    aggregationType: "auto",
  };
  return parseClicks(
    await request<unknown>(`/sites/${encodeURIComponent(requested)}/searchAnalytics/query`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
    range,
  );
}

/** Test-only cache reset; no production command exposes credentials or tokens. */
export function resetForTests(): void {
  tokenCache = null;
}

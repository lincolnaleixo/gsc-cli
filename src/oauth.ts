export const SEARCH_CONSOLE_SCOPE = "https://www.googleapis.com/auth/webmasters.readonly";
export const AUTHORIZATION_URI = "https://accounts.google.com/o/oauth2/v2/auth";
export const DEFAULT_TOKEN_URI = "https://oauth2.googleapis.com/token";
export const CALLBACK_PATH = "/oauth/callback";
export const START_PATH = "/start";

const DEFAULT_TIMEOUT_MS = 5 * 60 * 1000;
const DEFAULT_PORT = 0;
export interface BootstrapConfig {
  clientId: string;
  clientSecret: string;
  tokenUri: string;
}

export interface LoopbackServer {
  port: number;
  close: () => void | Promise<void>;
}

export type HttpHandler = (request: Request) => Response | Promise<Response>;
export type ServerFactory = (handler: HttpHandler, port: number) => LoopbackServer;
export type BrowserOpener = (url: string) => Promise<boolean>;

interface PipedStdin {
  write: (input: string | Uint8Array) => unknown;
  end: () => unknown;
}

export interface CredentialProcess {
  stdin: PipedStdin;
  stdout?: ReadableStream<Uint8Array> | null;
  stderr?: ReadableStream<Uint8Array> | null;
  exited: Promise<number>;
}

export type CredentialSpawn = (
  args: string[],
  options: { stdin: "pipe"; stdout: "pipe"; stderr: "pipe" },
) => CredentialProcess;

export interface PkcePair {
  state: string;
  verifier: string;
  challenge: string;
}

export interface OAuthOnboardingOptions {
  env?: Record<string, string | undefined>;
  fetchImpl?: typeof fetch;
  randomBytes?: (length: number) => Uint8Array;
  createServer?: ServerFactory;
  openBrowser?: BrowserOpener;
  setRefreshToken?: (refreshToken: string) => Promise<void>;
  showManualUrl?: (url: string) => void;
  port?: number;
  /**
   * Exact loopback callback URI registered with Google. The listener remains
   * on 127.0.0.1 at `port`; this value is used only in consent and exchange.
   */
  redirectUri?: string;
  timeoutMs?: number;
  noBrowser?: boolean;
}

export interface OAuthOnboardingResult {
  redirectUri: string;
  manualUrlShown: boolean;
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function hasControlCharacters(value: string): boolean {
  return /[\u0000-\u001f\u007f]/.test(value);
}

function safeCredential(value: unknown): value is string {
  return nonEmptyString(value) && !hasControlCharacters(value);
}

const LOOPBACK_REDIRECT_HOSTS = new Set(["localhost", "127.0.0.1"]);
const LOOPBACK_REDIRECT_PATTERN = /^http:\/\/(?:localhost|127\.0\.0\.1)(?::\d{1,5})?(\/[^?#]*)$/i;

function parseLoopbackRedirectUri(value: string): URL {
  if (
    !safeCredential(value) ||
    value !== value.trim() ||
    /\s/.test(value)
  ) {
    throw new Error(
      "OAuth redirect URI must be loopback HTTP (localhost or 127.0.0.1), without userinfo, query, or fragment, and include a path.",
    );
  }

  // Validate the authority before URL parsing. WHATWG URL normalizes alternate
  // IPv4 spellings (for example 127.1 or 2130706433) to 127.0.0.1; accepting
  // those would violate the deliberately narrow host allow-list below.
  if (!LOOPBACK_REDIRECT_PATTERN.test(value)) {
    throw new Error(
      "OAuth redirect URI must be loopback HTTP (localhost or 127.0.0.1), without userinfo, query, or fragment, and include a path.",
    );
  }

  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(
      "OAuth redirect URI must be loopback HTTP (localhost or 127.0.0.1), without userinfo, query, or fragment, and include a path.",
    );
  }

  // URL normalizes the hostname, so compare the parsed value while preserving
  // the caller's exact URI string for Google's consent and token requests.
  if (
    parsed.protocol !== "http:" ||
    !LOOPBACK_REDIRECT_HOSTS.has(parsed.hostname) ||
    parsed.username ||
    parsed.password ||
    parsed.search ||
    parsed.hash ||
    parsed.pathname.length === 0 ||
    parsed.pathname === START_PATH
  ) {
    throw new Error(
      "OAuth redirect URI must be loopback HTTP (localhost or 127.0.0.1), without userinfo, query, or fragment, and include a path other than /start.",
    );
  }

  return parsed;
}

/**
 * Validate and return the exact loopback redirect URI supplied by the caller.
 * The returned string is intentionally not normalized: Google requires an
 * exact registered URI in both the authorization and token requests.
 */
export function validateRedirectUri(value: string): string {
  parseLoopbackRedirectUri(value);
  return value;
}

/** Derive the callback route while applying the same redirect URI validation. */
export function callbackPathFromRedirectUri(redirectUri: string): string {
  return parseLoopbackRedirectUri(redirectUri).pathname;
}

function encodeBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function defaultRandomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function constantTimeEqual(left: string, right: string): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return difference === 0;
}

export async function pkceChallenge(verifier: string): Promise<string> {
  if (!safeCredential(verifier)) throw new Error("OAuth PKCE verifier is invalid.");
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return encodeBase64Url(new Uint8Array(digest));
}

export async function createPkcePair(
  randomBytes: (length: number) => Uint8Array = defaultRandomBytes,
): Promise<PkcePair> {
  const state = encodeBase64Url(randomBytes(32));
  const verifier = encodeBase64Url(randomBytes(32));
  if (!state || !verifier) throw new Error("OAuth security values could not be generated.");
  return { state, verifier, challenge: await pkceChallenge(verifier) };
}

export function bootstrapConfigFromEnv(
  env: Record<string, string | undefined> = process.env,
): BootstrapConfig {
  if (nonEmptyString(env.GOOGLE_SEARCH_CONSOLE_REFRESH_TOKEN)) {
    throw new Error("OAuth onboarding requires client ID and client secret only; omit GOOGLE_SEARCH_CONSOLE_REFRESH_TOKEN.");
  }

  const missing = [
    ["GOOGLE_SEARCH_CONSOLE_CLIENT_ID", env.GOOGLE_SEARCH_CONSOLE_CLIENT_ID],
    ["GOOGLE_SEARCH_CONSOLE_CLIENT_SECRET", env.GOOGLE_SEARCH_CONSOLE_CLIENT_SECRET],
  ]
    .filter(([, value]) => !safeCredential(value))
    .map(([name]) => name);
  if (missing.length > 0) {
    throw new Error(
      `OAuth bootstrap credentials missing: ${missing.join(", ")}. ` +
        "Provide them through the process environment.",
    );
  }

  const tokenUri = env.GOOGLE_SEARCH_CONSOLE_TOKEN_URI?.trim() || DEFAULT_TOKEN_URI;
  let parsedTokenUri: URL;
  try {
    parsedTokenUri = new URL(tokenUri);
  } catch {
    throw new Error("GOOGLE_SEARCH_CONSOLE_TOKEN_URI must be a valid HTTPS URL.");
  }
  if (
    parsedTokenUri.protocol !== "https:" ||
    hasControlCharacters(tokenUri) ||
    parsedTokenUri.username ||
    parsedTokenUri.password ||
    parsedTokenUri.search ||
    parsedTokenUri.hash
  ) {
    throw new Error("GOOGLE_SEARCH_CONSOLE_TOKEN_URI must use HTTPS without embedded credentials or query data.");
  }

  return {
    clientId: env.GOOGLE_SEARCH_CONSOLE_CLIENT_ID!.trim(),
    clientSecret: env.GOOGLE_SEARCH_CONSOLE_CLIENT_SECRET!.trim(),
    tokenUri,
  };
}

export function buildConsentUrl(
  config: BootstrapConfig,
  redirectUri: string,
  pair: Pick<PkcePair, "state" | "challenge">,
): string {
  const validatedRedirectUri = validateRedirectUri(redirectUri);
  const url = new URL(AUTHORIZATION_URI);
  url.search = new URLSearchParams({
    client_id: config.clientId,
    redirect_uri: validatedRedirectUri,
    response_type: "code",
    scope: SEARCH_CONSOLE_SCOPE,
    access_type: "offline",
    prompt: "consent",
    state: pair.state,
    code_challenge: pair.challenge,
    code_challenge_method: "S256",
  }).toString();
  return url.toString();
}

function genericOAuthError(status: number): Error {
  if (status === 400) return new Error("Google OAuth rejected the authorization exchange.");
  if (status === 401) return new Error("Google OAuth rejected the bootstrap client credentials.");
  return new Error(`Google OAuth authorization exchange failed (HTTP ${status}).`);
}

function parseRefreshToken(payload: unknown): string | null {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return null;
  const value = (payload as Record<string, unknown>).refresh_token;
  return safeCredential(value) ? value.trim() : null;
}

export async function exchangeAuthorizationCode(
  code: string,
  redirectUri: string,
  verifier: string,
  config: BootstrapConfig,
  fetchImpl: typeof fetch = fetch,
): Promise<string> {
  if (!safeCredential(code) || !safeCredential(verifier)) {
    throw new Error("Google OAuth callback values are invalid.");
  }
  const validatedRedirectUri = validateRedirectUri(redirectUri);

  const body = new URLSearchParams({
    client_id: config.clientId,
    client_secret: config.clientSecret,
    code,
    code_verifier: verifier,
    grant_type: "authorization_code",
    redirect_uri: validatedRedirectUri,
  });

  let response: Response;
  try {
    response = await fetchImpl(config.tokenUri, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
      body,
    });
  } catch {
    throw new Error("Google OAuth token exchange request failed.");
  }

  let payload: unknown = null;
  try {
    payload = await response.json();
  } catch {
    // The status-only error below intentionally avoids reflecting a provider body.
  }
  if (!response.ok) throw genericOAuthError(response.status);

  const refreshToken = parseRefreshToken(payload);
  if (!refreshToken) {
    throw new Error(
      "Google OAuth returned no refresh token; consent must include offline access and explicit consent.",
    );
  }
  return refreshToken;
}

function defaultServerFactory(handler: HttpHandler, port: number): LoopbackServer {
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port,
    fetch: handler,
  });
  if (!server.port) {
    server.stop();
    throw new Error("OAuth callback server did not expose a local port.");
  }
  return {
    port: server.port,
    close: () => server.stop(),
  };
}

async function defaultOpenBrowser(url: string): Promise<boolean> {
  if (process.platform === "linux" && !process.env.DISPLAY && !process.env.WAYLAND_DISPLAY) {
    return false;
  }

  const args = process.platform === "darwin"
    ? ["open", url]
    : process.platform === "win32"
      ? ["cmd", "/c", "start", "", url]
      : ["xdg-open", url];
  try {
    const child = Bun.spawn(args, { stdout: "ignore", stderr: "ignore" });
    void child.exited;
    return true;
  } catch {
    return false;
  }
}

async function drain(stream: ReadableStream<Uint8Array> | null | undefined): Promise<void> {
  if (!stream) return;
  try {
    await new Response(stream).arrayBuffer();
  } catch {
    // Child output is intentionally discarded, including if a wrapper misbehaves.
  }
}

function defaultCredentialSpawn(args: string[], options: {
  stdin: "pipe";
  stdout: "pipe";
  stderr: "pipe";
}): CredentialProcess {
  return Bun.spawn(args, options) as unknown as CredentialProcess;
}

/**
 * Store a newly issued refresh token through an explicitly configured command
 * or file path. Commands receive the token on stdin; output is drained and
 * never forwarded. File storage writes the token followed by a newline.
 */
export async function storeRefreshToken(
  refreshToken: string,
  options: {
    env?: Record<string, string | undefined>;
    spawn?: CredentialSpawn;
    writeFile?: (path: string, content: string) => Promise<number>;
  } = {},
): Promise<void> {
  if (!safeCredential(refreshToken)) throw new Error("Google OAuth returned an invalid refresh token.");

  const env = options.env ?? process.env;
  const command = env.GOOGLE_SEARCH_CONSOLE_CREDENTIAL_COMMAND?.trim();
  const path = env.GOOGLE_SEARCH_CONSOLE_REFRESH_TOKEN_FILE?.trim();
  if (command && path) {
    throw new Error("Configure only one of GOOGLE_SEARCH_CONSOLE_CREDENTIAL_COMMAND or GOOGLE_SEARCH_CONSOLE_REFRESH_TOKEN_FILE.");
  }
  if (path) {
    try {
      await (options.writeFile ?? ((filePath, content) => Bun.write(filePath, content)))(path, `${refreshToken}\n`);
      return;
    } catch {
      throw new Error("Credential file could not store the Google Search Console refresh token.");
    }
  }
  if (!command) {
    throw new Error("OAuth onboarding requires GOOGLE_SEARCH_CONSOLE_CREDENTIAL_COMMAND or GOOGLE_SEARCH_CONSOLE_REFRESH_TOKEN_FILE.");
  }

  const spawn = options.spawn ?? defaultCredentialSpawn;
  let child: CredentialProcess;
  try {
    child = spawn([command], { stdin: "pipe", stdout: "pipe", stderr: "pipe" });
    await Promise.resolve(child.stdin.write(`${refreshToken}\n`));
    await Promise.resolve(child.stdin.end());
  } catch {
    throw new Error("Credential command could not receive the Google Search Console refresh token.");
  }

  const drains = [drain(child.stdout), drain(child.stderr)];
  let exitCode: number;
  try {
    exitCode = await child.exited;
  } catch {
    await Promise.all(drains);
    throw new Error("Credential command could not store the Google Search Console refresh token.");
  }
  await Promise.all(drains);
  if (exitCode !== 0) {
    throw new Error("Credential command rejected the Google Search Console refresh token.");
  }
}

function callbackResponse(message: string, status = 200): Response {
  return new Response(message, {
    status,
    headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" },
  });
}

function oauthDenialMessage(error: string): string {
  if (error === "redirect_uri_mismatch") {
    return "Google rejected this loopback redirect URI. Use a Desktop OAuth client, or register the exact loopback URI shown in the onboarding instructions and rerun with a fixed --port.";
  }
  if (error === "access_denied") return "Google consent was denied; no credential was stored.";
  return "Google did not complete authorization; no credential was stored.";
}

function validatePort(port: number): void {
  if (!Number.isInteger(port) || port < 0 || port > 65_535) {
    throw new Error("OAuth callback port must be an integer from 0 to 65535.");
  }
}

function validateTimeout(timeoutMs: number): void {
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1_000 || timeoutMs > 15 * 60 * 1000) {
    throw new Error("OAuth callback timeout must be between 1 and 900 seconds.");
  }
}

export async function runOAuthOnboarding(
  options: OAuthOnboardingOptions = {},
): Promise<OAuthOnboardingResult> {
  const config = bootstrapConfigFromEnv(options.env);
  const port = options.port ?? DEFAULT_PORT;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const requestedRedirectUri = options.redirectUri;
  if (requestedRedirectUri !== undefined) validateRedirectUri(requestedRedirectUri);
  validatePort(port);
  validateTimeout(timeoutMs);

  const pair = await createPkcePair(options.randomBytes);
  let consentUrl = "";
  let callbackPath = CALLBACK_PATH;
  let settled = false;
  let resolveCallback!: (code: string) => void;
  let rejectCallback!: (error: Error) => void;
  const callbackCode = new Promise<string>((resolve, reject) => {
    resolveCallback = resolve;
    rejectCallback = reject;
  });

  const handler: HttpHandler = async (request) => {
    const url = new URL(request.url);
    if (request.method !== "GET") return callbackResponse("Method not allowed.", 405);
    if (url.pathname === START_PATH) {
      if (!consentUrl) return callbackResponse("Authorization is not ready.", 503);
      return new Response(null, {
        status: 302,
        headers: { Location: consentUrl, "Cache-Control": "no-store" },
      });
    }
    if (url.pathname !== callbackPath) return callbackResponse("Not found.", 404);

    const receivedState = url.searchParams.get("state") ?? "";
    if (!constantTimeEqual(receivedState, pair.state)) {
      return callbackResponse("Invalid OAuth callback.", 400);
    }

    const denial = url.searchParams.get("error");
    if (denial) {
      if (!settled) {
        settled = true;
        rejectCallback(new Error(oauthDenialMessage(denial)));
      }
      return callbackResponse("Authorization was not completed. You may close this tab.", 400);
    }

    const code = url.searchParams.get("code") ?? "";
    if (!safeCredential(code)) {
      if (!settled) {
        settled = true;
        rejectCallback(new Error("Google OAuth callback did not include an authorization code."));
      }
      return callbackResponse("Authorization was not completed. You may close this tab.", 400);
    }

    if (!settled) {
      settled = true;
      resolveCallback(code);
    }
    return callbackResponse("Authorization received. You may close this tab.");
  };

  let server: LoopbackServer;
  try {
    server = (options.createServer ?? defaultServerFactory)(handler, port);
  } catch {
    throw new Error("Could not bind the OAuth callback to 127.0.0.1.");
  }
  if (!Number.isInteger(server.port) || server.port < 1 || server.port > 65_535) {
    await server.close();
    throw new Error("OAuth callback server returned an invalid local port.");
  }

  const redirectUri = requestedRedirectUri ?? `http://127.0.0.1:${server.port}${CALLBACK_PATH}`;
  callbackPath = callbackPathFromRedirectUri(redirectUri);
  const startUrl = `http://127.0.0.1:${server.port}${START_PATH}`;
  consentUrl = buildConsentUrl(config, redirectUri, pair);
  let manualUrlShown = false;
  const showManualUrl = options.showManualUrl ?? ((url: string) => console.log(`Open this local URL in a browser: ${url}`));

  try {
    let browserOpened = false;
    if (!options.noBrowser) {
      try {
        browserOpened = await (options.openBrowser ?? defaultOpenBrowser)(consentUrl);
      } catch {
        browserOpened = false;
      }
    }
    if (!browserOpened) {
      manualUrlShown = true;
      showManualUrl(startUrl);
    }

    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        rejectCallback(new Error("OAuth callback timed out; rerun onboarding and complete consent before the timeout."));
      }
    }, timeoutMs);

    try {
      const code = await callbackCode;
      const refreshToken = await exchangeAuthorizationCode(
        code,
        redirectUri,
        pair.verifier,
        config,
        options.fetchImpl,
      );
      await (options.setRefreshToken ?? ((token: string) => storeRefreshToken(token)))(refreshToken);
    } finally {
      clearTimeout(timer);
    }
  } finally {
    await server.close();
  }

  return { redirectUri, manualUrlShown };
}

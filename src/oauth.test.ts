import { afterEach, describe, expect, test } from "bun:test";
import {
  AUTHORIZATION_URI,
  CALLBACK_PATH,
  SEARCH_CONSOLE_SCOPE,
  START_PATH,
  VAULT_REFRESH_TOKEN_REFERENCE,
  buildConsentUrl,
  bootstrapConfigFromEnv,
  callbackPathFromRedirectUri,
  createPkcePair,
  exchangeAuthorizationCode,
  pkceChallenge,
  runOAuthOnboarding,
  setRefreshTokenInVault,
  type BootstrapConfig,
  type HttpHandler,
  type LoopbackServer,
  type VaultSetProcess,
  validateRedirectUri,
} from "./oauth.ts";

const TOKEN_URI = "https://oauth2.example.test/token";
const CLIENT_ID = "fixture-client-id.apps.googleusercontent.com";
const CLIENT_SECRET = "fixture-client-secret-value";
const REFRESH_TOKEN = "fixture-refresh-token-value";
const AUTH_CODE = "fixture-authorization-code";
const REDIRECT_URI = "http://127.0.0.1:43817/oauth/callback";
const REGISTERED_REDIRECT_URI = "http://localhost:8888/callback";
const config: BootstrapConfig = { clientId: CLIENT_ID, clientSecret: CLIENT_SECRET, tokenUri: TOKEN_URI };

let fakeServer: {
  handler: HttpHandler;
  port: number;
  closed: boolean;
} | null = null;

function fakeServerFactory(handler: HttpHandler, port: number): LoopbackServer {
  const state = { handler, port: port || 43817, closed: false };
  fakeServer = state;
  return {
    port: state.port,
    close: () => {
      state.closed = true;
    },
  };
}

function env(): Record<string, string> {
  return {
    GOOGLE_SEARCH_CONSOLE_CLIENT_ID: CLIENT_ID,
    GOOGLE_SEARCH_CONSOLE_CLIENT_SECRET: CLIENT_SECRET,
    GOOGLE_SEARCH_CONSOLE_TOKEN_URI: TOKEN_URI,
  };
}

function randomBytesFactory(): (length: number) => Uint8Array {
  let call = 0;
  return (length) => new Uint8Array(length).fill(++call);
}

async function waitForFakeServer(): Promise<NonNullable<typeof fakeServer>> {
  for (let attempt = 0; attempt < 10 && !fakeServer; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  if (!fakeServer) throw new Error("test server was not created");
  return fakeServer;
}

function tokenResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function byteStream(value: string): ReadableStream<Uint8Array> {
  return new ReadableStream({
    start(controller) {
      controller.enqueue(new TextEncoder().encode(value));
      controller.close();
    },
  });
}

afterEach(() => {
  fakeServer = null;
});

describe("OAuth security primitives", () => {
  test("requires the dedicated bootstrap profile and rejects an injected refresh token", () => {
    expect(() => bootstrapConfigFromEnv({
      ...env(),
      GOOGLE_SEARCH_CONSOLE_REFRESH_TOKEN: REFRESH_TOKEN,
    })).toThrow("bootstrap Vault profile without a refresh token");
    expect(() => bootstrapConfigFromEnv({
      ...env(),
      GOOGLE_SEARCH_CONSOLE_TOKEN_URI: "https://user:password@example.test/token?secret=value",
    })).toThrow("without embedded credentials or query data");
  });

  test("creates S256 PKCE with the RFC verifier vector", async () => {
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    await expect(pkceChallenge(verifier)).resolves.toBe("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
  });

  test("generates independent state and verifier values", async () => {
    const pair = await createPkcePair(randomBytesFactory());
    expect(pair.state).toHaveLength(43);
    expect(pair.verifier).toHaveLength(43);
    expect(pair.state).not.toBe(pair.verifier);
    expect(pair.challenge).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  test("consent URL has exact scope and no client secret or refresh token", () => {
    const url = new URL(buildConsentUrl(config, REDIRECT_URI, {
      state: "state-value",
      challenge: "challenge-value",
    }));
    expect(url.origin + url.pathname).toBe(AUTHORIZATION_URI);
    expect(url.searchParams.get("scope")).toBe(SEARCH_CONSOLE_SCOPE);
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("access_type")).toBe("offline");
    expect(url.searchParams.get("prompt")).toBe("consent");
    expect(url.searchParams.get("client_secret")).toBeNull();
    expect(url.toString()).not.toContain(CLIENT_SECRET);
    expect(url.toString()).not.toContain(REFRESH_TOKEN);
  });

  test("accepts only explicit loopback HTTP redirect paths and preserves the exact URI", () => {
    expect(validateRedirectUri(REGISTERED_REDIRECT_URI)).toBe(REGISTERED_REDIRECT_URI);
    expect(validateRedirectUri("http://127.0.0.1:8888/callback")).toBe("http://127.0.0.1:8888/callback");
    expect(callbackPathFromRedirectUri(REGISTERED_REDIRECT_URI)).toBe("/callback");

    const rejected = [
      "",
      "http://localhost:8888",
      "https://localhost:8888/callback",
      "http://example.test:8888/callback",
      "http://user:password@localhost:8888/callback",
      "http://localhost:8888/callback?state=unexpected",
      "http://localhost:8888/callback#fragment",
      "http://localhost:8888/start",
      "http://[::1]:8888/callback",
      "http://127.1:8888/callback",
      "http://2130706433:8888/callback",
    ];
    for (const redirectUri of rejected) {
      expect(() => validateRedirectUri(redirectUri), redirectUri).toThrow("loopback HTTP");
    }
  });
});

describe("OAuth token exchange", () => {
  test("sends the secret only in the HTTPS POST body and returns the refresh token in memory", async () => {
    let requestedUrl = "";
    let requestBody = "";
    const refreshToken = await exchangeAuthorizationCode(
      AUTH_CODE,
      REDIRECT_URI,
      "verifier-value",
      config,
      (async (input: string | URL, init?: RequestInit) => {
        requestedUrl = String(input);
        requestBody = String(init?.body);
        return tokenResponse({ access_token: "fixture-access-token", refresh_token: REFRESH_TOKEN });
      }) as unknown as typeof fetch,
    );

    const form = new URLSearchParams(requestBody);
    expect(requestedUrl).toBe(TOKEN_URI);
    expect(form.get("client_id")).toBe(CLIENT_ID);
    expect(form.get("client_secret")).toBe(CLIENT_SECRET);
    expect(form.get("code")).toBe(AUTH_CODE);
    expect(form.get("code_verifier")).toBe("verifier-value");
    expect(form.get("refresh_token")).toBeNull();
    expect(refreshToken).toBe(REFRESH_TOKEN);
  });

  test("does not reflect provider detail when exchange fails", async () => {
    const error = await exchangeAuthorizationCode(
      AUTH_CODE,
      REDIRECT_URI,
      "verifier-value",
      config,
      (async () => {
        throw new Error(`${REFRESH_TOKEN} ${CLIENT_SECRET}`);
      }) as unknown as typeof fetch,
    ).catch((value: unknown) => value);
    expect(error).toBeInstanceOf(Error);
    expect(String(error)).not.toContain(REFRESH_TOKEN);
    expect(String(error)).not.toContain(CLIENT_SECRET);
  });

  test("rejects a successful response without a refresh token", async () => {
    await expect(exchangeAuthorizationCode(
      AUTH_CODE,
      REDIRECT_URI,
      "verifier-value",
      config,
      (async () => tokenResponse({ access_token: "fixture-access-token" })) as unknown as typeof fetch,
    )).rejects.toThrow("no refresh token");
  });
});

describe("loopback OAuth onboarding", () => {
  test("uses state and PKCE, shows only a local fallback URL, and stores a successful grant", async () => {
    let consentUrl = "";
    let manualUrl = "";
    let storedToken = "";
    const onboarding = runOAuthOnboarding({
      env: env(),
      createServer: fakeServerFactory,
      randomBytes: randomBytesFactory(),
      openBrowser: async (url) => {
        consentUrl = url;
        return false;
      },
      showManualUrl: (url) => {
        manualUrl = url;
      },
      fetchImpl: (async (input, init) => {
        expect(String(input)).toBe(TOKEN_URI);
        const form = new URLSearchParams(String(init?.body));
        expect(form.get("client_secret")).toBe(CLIENT_SECRET);
        expect(form.get("code_verifier")).toBeTruthy();
        expect(form.get("redirect_uri")).toBe(REDIRECT_URI);
        return tokenResponse({ refresh_token: REFRESH_TOKEN });
      }) as typeof fetch,
      setRefreshToken: async (token) => {
        storedToken = token;
      },
      noBrowser: false,
      timeoutMs: 1_000,
    });
    const server = await waitForFakeServer();
    const startResponse = await server.handler(new Request(`http://127.0.0.1:${server.port}${START_PATH}`));
    const location = startResponse.headers.get("location");
    expect(startResponse.status).toBe(302);
    expect(location).toBeTruthy();
    consentUrl = location!;
    const consent = new URL(consentUrl);
    const state = consent.searchParams.get("state");
    expect(state).toBeTruthy();
    expect(consent.searchParams.get("code_challenge")).toBeTruthy();
    expect(consentUrl).not.toContain(CLIENT_SECRET);
    expect(consentUrl).not.toContain(REFRESH_TOKEN);
    expect(manualUrl).toBe(`http://127.0.0.1:${server.port}${START_PATH}`);

    const callback = await server.handler(new Request(
      `http://127.0.0.1:${server.port}${CALLBACK_PATH}?state=${encodeURIComponent(state!)}&code=${AUTH_CODE}`,
    ));
    expect(callback.status).toBe(200);
    const result = await onboarding;
    expect(result).toEqual({
      redirectUri: REDIRECT_URI,
      manualUrlShown: true,
    });
    expect(storedToken).toBe(REFRESH_TOKEN);
    expect(server.closed).toBe(true);
    expect(await callback.text()).not.toContain(REFRESH_TOKEN);
  });

  test("rejects a forged state without consuming the real callback", async () => {
    const onboarding = runOAuthOnboarding({
      env: env(),
      createServer: fakeServerFactory,
      randomBytes: randomBytesFactory(),
      openBrowser: async () => true,
      fetchImpl: (async () => tokenResponse({ refresh_token: REFRESH_TOKEN })) as unknown as typeof fetch,
      setRefreshToken: async () => undefined,
      timeoutMs: 1_000,
    });
    const server = await waitForFakeServer();
    const startResponse = await server.handler(new Request(`http://127.0.0.1:${server.port}${START_PATH}`));
    const consent = new URL(startResponse.headers.get("location")!);
    const forged = await server.handler(new Request(
      `http://127.0.0.1:${server.port}${CALLBACK_PATH}?state=wrong-state&code=${AUTH_CODE}`,
    ));
    expect(forged.status).toBe(400);
    const valid = await server.handler(new Request(
      `http://127.0.0.1:${server.port}${CALLBACK_PATH}?state=${encodeURIComponent(consent.searchParams.get("state")!)}&code=${AUTH_CODE}`,
    ));
    expect(valid.status).toBe(200);
    await expect(onboarding).resolves.toMatchObject({ manualUrlShown: false });
  });

  test("separates the listener port from the exact registered redirect URI and derives its callback path", async () => {
    let manualUrl = "";
    type CustomServer = { handler: HttpHandler; port: number; closed: boolean };
    let resolveServer!: (server: CustomServer) => void;
    const serverReady = new Promise<CustomServer>((resolve) => {
      resolveServer = resolve;
    });
    const onboarding = runOAuthOnboarding({
      env: env(),
      port: 43817,
      redirectUri: REGISTERED_REDIRECT_URI,
      createServer: (handler, port) => {
        const server: CustomServer = { handler, port, closed: false };
        resolveServer(server);
        return {
          port: server.port,
          close: () => {
            server.closed = true;
          },
        };
      },
      noBrowser: true,
      showManualUrl: (url) => {
        manualUrl = url;
      },
      fetchImpl: (async (input, init) => {
        expect(String(input)).toBe(TOKEN_URI);
        const form = new URLSearchParams(String(init?.body));
        expect(form.get("redirect_uri")).toBe(REGISTERED_REDIRECT_URI);
        expect(form.get("client_secret")).toBe(CLIENT_SECRET);
        return tokenResponse({ refresh_token: REFRESH_TOKEN });
      }) as typeof fetch,
      setRefreshToken: async (token) => {
        expect(token).toBe(REFRESH_TOKEN);
      },
      timeoutMs: 1_000,
    });
    const server = await serverReady;
    expect(manualUrl).toBe(`http://127.0.0.1:${server.port}${START_PATH}`);

    const startResponse = await server.handler(new Request(manualUrl));
    expect(startResponse.status).toBe(302);
    const consentUrl = startResponse.headers.get("location");
    expect(consentUrl).toBeTruthy();
    const consent = new URL(consentUrl!);
    expect(consent.searchParams.get("redirect_uri")).toBe(REGISTERED_REDIRECT_URI);
    expect(consentUrl).not.toContain(CLIENT_SECRET);
    expect(consentUrl).not.toContain(REFRESH_TOKEN);

    const state = consent.searchParams.get("state")!;
    const defaultPath = await server.handler(new Request(
      `http://127.0.0.1:${server.port}${CALLBACK_PATH}?state=${encodeURIComponent(state)}&code=${AUTH_CODE}`,
    ));
    expect(defaultPath.status).toBe(404);

    const callback = await server.handler(new Request(
      `http://127.0.0.1:${server.port}/callback?state=${encodeURIComponent(state)}&code=${AUTH_CODE}`,
    ));
    expect(callback.status).toBe(200);
    await expect(onboarding).resolves.toEqual({
      redirectUri: REGISTERED_REDIRECT_URI,
      manualUrlShown: true,
    });
  });

  test("rejects an unsafe custom redirect before starting a listener", async () => {
    let serverCreated = false;
    const onboarding = runOAuthOnboarding({
      env: env(),
      redirectUri: "https://example.test/callback",
      createServer: (handler, port) => {
        serverCreated = true;
        return fakeServerFactory(handler, port);
      },
    });
    await expect(onboarding).rejects.toThrow("loopback HTTP");
    expect(serverCreated).toBe(false);
  });

  test("handles OAuth denial without reflecting error details", async () => {
    const onboarding = runOAuthOnboarding({
      env: env(),
      createServer: fakeServerFactory,
      randomBytes: randomBytesFactory(),
      openBrowser: async () => true,
      timeoutMs: 1_000,
    });
    const server = await waitForFakeServer();
    const startResponse = await server.handler(new Request(`http://127.0.0.1:${server.port}${START_PATH}`));
    const state = new URL(startResponse.headers.get("location")!).searchParams.get("state")!;
    const response = await server.handler(new Request(
      `http://127.0.0.1:${server.port}${CALLBACK_PATH}?state=${encodeURIComponent(state)}&error=access_denied&error_description=${encodeURIComponent(`${REFRESH_TOKEN} ${CLIENT_SECRET}`)}`,
    ));
    expect(response.status).toBe(400);
    expect(await response.text()).not.toContain(REFRESH_TOKEN);
    const error = await onboarding.catch((value: unknown) => value);
    expect(String(error)).toContain("consent was denied");
    expect(String(error)).not.toContain(REFRESH_TOKEN);
    expect(String(error)).not.toContain(CLIENT_SECRET);
  });

  test("reports an incompatible web-client redirect safely", async () => {
    const onboarding = runOAuthOnboarding({
      env: env(),
      createServer: fakeServerFactory,
      randomBytes: randomBytesFactory(),
      openBrowser: async () => true,
      timeoutMs: 1_000,
    });
    const server = await waitForFakeServer();
    const startResponse = await server.handler(new Request(`http://127.0.0.1:${server.port}${START_PATH}`));
    const state = new URL(startResponse.headers.get("location")!).searchParams.get("state")!;
    await server.handler(new Request(
      `http://127.0.0.1:${server.port}${CALLBACK_PATH}?state=${encodeURIComponent(state)}&error=redirect_uri_mismatch&error_description=${encodeURIComponent(`${REFRESH_TOKEN} ${CLIENT_SECRET}`)}`,
    ));
    const error = await onboarding.catch((value: unknown) => value);
    expect(String(error)).toContain("loopback redirect URI");
    expect(String(error)).toContain("Desktop OAuth client");
    expect(String(error)).not.toContain(REFRESH_TOKEN);
    expect(String(error)).not.toContain(CLIENT_SECRET);
  });

  test("times out and closes the listener when consent never returns", async () => {
    const onboarding = runOAuthOnboarding({
      env: env(),
      createServer: fakeServerFactory,
      randomBytes: randomBytesFactory(),
      openBrowser: async () => true,
      timeoutMs: 1_000,
    });
    const server = await waitForFakeServer();
    await expect(onboarding).rejects.toThrow("timed out");
    expect(server.closed).toBe(true);
  });

  test("binds the production listener to loopback and serves a value-free start redirect", async () => {
    let manualUrl = "";
    const onboarding = runOAuthOnboarding({
      env: env(),
      noBrowser: true,
      showManualUrl: (url) => {
        manualUrl = url;
      },
      openBrowser: async () => false,
      fetchImpl: (async (input: string | URL, init?: RequestInit) => {
        expect(String(input)).toBe(TOKEN_URI);
        const form = new URLSearchParams(String(init?.body));
        expect(form.get("client_secret")).toBe(CLIENT_SECRET);
        return tokenResponse({ refresh_token: REFRESH_TOKEN });
      }) as unknown as typeof fetch,
      setRefreshToken: async (token) => {
        expect(token).toBe(REFRESH_TOKEN);
      },
      timeoutMs: 1_000,
    });
    for (let attempt = 0; attempt < 20 && !manualUrl; attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
    expect(manualUrl).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/start$/);
    const startResponse = await fetch(manualUrl, { redirect: "manual" });
    const consentUrl = startResponse.headers.get("location");
    expect(startResponse.status).toBe(302);
    expect(consentUrl).toBeTruthy();
    expect(consentUrl).not.toContain(CLIENT_SECRET);
    expect(consentUrl).not.toContain(REFRESH_TOKEN);
    const state = new URL(consentUrl!).searchParams.get("state")!;
    const callbackUrl = `${manualUrl.replace(START_PATH, CALLBACK_PATH)}?state=${encodeURIComponent(state)}&code=${AUTH_CODE}`;
    await expect(fetch(callbackUrl)).resolves.toMatchObject({ status: 200 });
    await expect(onboarding).resolves.toMatchObject({ manualUrlShown: true });
  });
});

describe("Vault refresh-token handoff", () => {
  test("uses only fixed argv, writes the token to stdin, drains child output, and emits no logs", async () => {
    let args: string[] = [];
    let input = "";
    let options: unknown;
    const originalLog = console.log;
    const originalError = console.error;
    let output = "";
    console.log = (...values: unknown[]) => {
      output += values.join(" ");
    };
    console.error = (...values: unknown[]) => {
      output += values.join(" ");
    };
    try {
      await setRefreshTokenInVault(REFRESH_TOKEN, (nextArgs, nextOptions) => {
        args = nextArgs;
        options = nextOptions;
        const child: VaultSetProcess = {
          stdin: {
            write(value) {
              input += typeof value === "string" ? value : new TextDecoder().decode(value);
            },
            end: () => undefined,
          },
          stdout: byteStream(REFRESH_TOKEN),
          stderr: byteStream(REFRESH_TOKEN),
          exited: Promise.resolve(0),
        };
        return child;
      });
    } finally {
      console.log = originalLog;
      console.error = originalError;
    }
    expect(args).toEqual([
      "/home/robot/.local/bin/system-vault",
      "set",
      VAULT_REFRESH_TOKEN_REFERENCE,
      "--confirm",
    ]);
    expect(JSON.stringify(options)).toContain('"stdin":"pipe"');
    expect(input).toBe(`${REFRESH_TOKEN}\n`);
    expect(args.join(" ")).not.toContain(REFRESH_TOKEN);
    expect(output).toBe("");
  });

  test("does not reflect token values if the Vault process fails", async () => {
    let output = "";
    const originalError = console.error;
    console.error = (...values: unknown[]) => {
      output += values.join(" ");
    };
    try {
      const error = await setRefreshTokenInVault(REFRESH_TOKEN, () => {
        throw new Error(`${REFRESH_TOKEN} ${CLIENT_SECRET}`);
      }).catch((value: unknown) => value);
      expect(String(error)).toContain("System Vault");
      expect(String(error)).not.toContain(REFRESH_TOKEN);
      expect(String(error)).not.toContain(CLIENT_SECRET);
    } finally {
      console.error = originalError;
    }
    expect(output).toBe("");
  });
});

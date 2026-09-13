#!/usr/bin/env bun
import * as searchConsole from "./client.ts";
import { runOAuthOnboarding } from "./oauth.ts";
import type { SearchConsoleProperty, SearchConsoleClicks } from "./types.ts";

type FlagValue = string | boolean;

export interface ParsedArgs {
  positional: string[];
  flags: Record<string, FlagValue>;
}

const BOOLEAN_FLAGS = new Set(["json", "confirm", "no-browser"]);
const COMMANDS = new Set(["properties", "verify", "clicks", "onboard", "help"]);
const ALLOWED_FLAGS: Record<string, ReadonlySet<string>> = {
  properties: new Set(["json"]),
  verify: new Set(["json"]),
  clicks: new Set(["days", "end-date", "json"]),
  onboard: new Set(["confirm", "no-browser", "port", "redirect-uri", "timeout-seconds"]),
  help: new Set(),
};

export class CliError extends Error {
  constructor(message: string, readonly exitCode = 1) {
    super(message);
  }
}

export function parseArgs(input: string[]): ParsedArgs {
  const positional: string[] = [];
  const flags: Record<string, FlagValue> = {};

  for (let index = 0; index < input.length; index += 1) {
    const item = input[index]!;
    if (!item.startsWith("--")) {
      positional.push(item);
      continue;
    }

    const key = item.slice(2);
    if (!key) throw new CliError("empty flag");
    if (key in flags) throw new CliError(`duplicate flag: --${key}`);
    if (BOOLEAN_FLAGS.has(key)) {
      flags[key] = true;
      continue;
    }

    const value = input[index + 1];
    if (value === undefined || value.startsWith("--")) {
      throw new CliError(`--${key} requires a value`);
    }
    flags[key] = value;
    index += 1;
  }

  return { positional, flags };
}

export function assertAllowedFlags(command: string, flags: Record<string, FlagValue>): void {
  const allowed = ALLOWED_FLAGS[command];
  if (!allowed) throw new CliError(`unknown command: ${command}\n\n${usage()}`);
  for (const key of Object.keys(flags)) {
    if (!allowed.has(key)) throw new CliError(`unknown flag for ${command}: --${key}`);
  }
}

function flagString(flags: Record<string, FlagValue>, name: string): string | undefined {
  const value = flags[name];
  return typeof value === "string" ? value : undefined;
}

function hasFlag(flags: Record<string, FlagValue>, name: string): boolean {
  return flags[name] === true;
}

export function assertOnboardingConfirmation(flags: Record<string, FlagValue>): void {
  if (!hasFlag(flags, "confirm")) {
    throw new CliError("onboard requires explicit --confirm because it creates or rotates a Vault secret");
  }
}

function required(positionals: string[], index: number, label: string): string {
  const value = positionals[index];
  if (!value) throw new CliError(`missing ${label}`);
  return value;
}

function assertArity(positionals: string[], count: number, syntax: string): void {
  if (positionals.length !== count) throw new CliError(`usage: ${syntax}`);
}

function parseDays(flags: Record<string, FlagValue>): number {
  const raw = flagString(flags, "days");
  if (raw === undefined) throw new CliError("missing --days (an integer from 1 to 365 is required)");
  const days = Number(raw);
  if (!Number.isInteger(days) || days < 1 || days > 365) {
    throw new CliError("--days must be an integer from 1 to 365");
  }
  return days;
}

function parseBoundedInteger(
  flags: Record<string, FlagValue>,
  name: string,
  minimum: number,
  maximum: number,
): number | undefined {
  const raw = flagString(flags, name);
  if (raw === undefined) return undefined;
  const value = Number(raw);
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new CliError(`--${name} must be an integer from ${minimum} to ${maximum}`);
  }
  return value;
}

/** Safe CLI projection: API field names and any unrequested payload are omitted. */
export function propertySummary(property: SearchConsoleProperty): {
  property: string;
  permission: string;
} {
  return {
    property: property.siteUrl,
    permission: property.permissionLevel,
  };
}

/** Safe CLI projection for aggregate clicks; no query/page/dimension data. */
export function clicksSummary(
  property: SearchConsoleProperty,
  clicks: SearchConsoleClicks,
): {
  property: string;
  permission: string;
  totalClicks: number;
  startDate: string;
  endDate: string;
  sourceHealthy: true;
} {
  return {
    property: property.siteUrl,
    permission: property.permissionLevel,
    totalClicks: clicks.totalClicks,
    startDate: clicks.startDate,
    endDate: clicks.endDate,
    sourceHealthy: clicks.sourceHealthy,
  };
}

export function usage(): string {
  return `Google Search Console (read-only aggregate reporting)

Usage: /home/robot/.local/bin/system-vault run google-search-console -- bun <skill-directory>/scripts/cli.ts <command> [args]

Commands:
  properties [--json]                    List accessible properties and permissions
  verify <property> [--json]             Confirm one exact accessible property
  clicks <property> --days N [options]   Aggregate web clicks for 1 to 365 days
    --end-date YYYY-MM-DD                Inclusive range end (defaults to today)
    --json                                Emit only safe aggregate JSON
  onboard --confirm [options]             Obtain offline consent and store the refresh token
    --port N                               Fixed loopback port (0 lets the OS choose one)
    --redirect-uri URI                     Exact registered loopback callback URI
    --timeout-seconds N                    Callback timeout from 30 to 900 seconds
    --no-browser                           Show a local helper URL instead of opening a browser
  help                                    Show this help

The OAuth reporting profile must be authorized with webmasters.readonly. For
onboarding, run this command through the dedicated bootstrap profile, which
contains only the client ID, client secret, and token URI:

  /home/robot/.local/bin/system-vault run google-search-console-bootstrap -- bun <skill-directory>/scripts/cli.ts onboard --confirm

Onboarding uses a 127.0.0.1 callback, state, and PKCE. It never prints the
Google consent URL. If no browser can be opened, it prints only a local
/start URL that redirects server-side. A Desktop OAuth client supports this
loopback flow. A Web client must have the exact fixed callback URI registered.
By default, the listener port and registered callback port are the same; use
--port N and register http://127.0.0.1:N/oauth/callback in Google Cloud. To
keep a listener on one local port while a proxy or tunnel forwards a
registered callback from another, pass the exact URI with --redirect-uri, for
example --port 43817 --redirect-uri http://localhost:8888/callback. Only HTTP
localhost or 127.0.0.1 URIs without userinfo, query, or fragment are allowed.
The callback path is taken from that URI.

Properties are matched exactly; a missing, stale, denied, or malformed source
is an error, not zero clicks. A valid empty result is reported as zero with
sourceHealthy=true. No query, page, dimension, or personal data is returned.`;
}

function printProperties(properties: SearchConsoleProperty[], json: boolean): void {
  const safe = properties.map(propertySummary);
  if (json) {
    console.log(JSON.stringify(safe, null, 2));
    return;
  }
  if (safe.length === 0) {
    console.log("No accessible Google Search Console properties found");
    return;
  }

  console.log("\nProperty                                      | Permission");
  console.log("----------------------------------------------|----------------");
  for (const entry of safe) {
    console.log(`${entry.property.padEnd(46).slice(0, 46)} | ${entry.permission}`);
  }
  console.log(`\nTotal: ${safe.length} propert${safe.length === 1 ? "y" : "ies"}`);
}

function printVerified(property: SearchConsoleProperty, json: boolean): void {
  const safe = propertySummary(property);
  if (json) {
    console.log(JSON.stringify(safe, null, 2));
    return;
  }
  console.log(`\nProperty: ${safe.property}\nPermission: ${safe.permission}`);
}

function printClicks(
  property: SearchConsoleProperty,
  clicks: SearchConsoleClicks,
  json: boolean,
): void {
  const safe = clicksSummary(property, clicks);
  if (json) {
    console.log(JSON.stringify(safe, null, 2));
    return;
  }
  console.log(`
Property:       ${safe.property}
Permission:     ${safe.permission}
Total clicks:   ${safe.totalClicks}
Date range:     ${safe.startDate} through ${safe.endDate}
Source healthy: yes`);
}

async function main(): Promise<void> {
  let parsed: ParsedArgs;
  try {
    parsed = parseArgs(process.argv.slice(2));
    const [rawCommand, ...args] = parsed.positional;
    const command = rawCommand?.toLowerCase() || "help";
    assertAllowedFlags(command, parsed.flags);
    if (!COMMANDS.has(command)) throw new CliError(`unknown command: ${command}\n\n${usage()}`);

    if (command === "help") {
      assertArity(args, 0, "help");
      console.log(usage());
      return;
    }

    const json = hasFlag(parsed.flags, "json");
    switch (command) {
      case "properties":
        assertArity(args, 0, "properties [--json]");
        printProperties(await searchConsole.listProperties(), json);
        return;
      case "verify":
        assertArity(args, 1, "verify <property> [--json]");
        printVerified(await searchConsole.verifyProperty(required(args, 0, "property")), json);
        return;
      case "clicks": {
        assertArity(args, 1, "clicks <property> --days N [--end-date YYYY-MM-DD] [--json]");
        const property = await searchConsole.verifyProperty(required(args, 0, "property"));
        const clicks = await searchConsole.queryClicks(
          property.siteUrl,
          parseDays(parsed.flags),
          flagString(parsed.flags, "end-date"),
        );
        printClicks(property, clicks, json);
        return;
      }
      case "onboard": {
        assertArity(args, 0, "onboard --confirm [--port N] [--redirect-uri URI] [--timeout-seconds N] [--no-browser]");
        assertOnboardingConfirmation(parsed.flags);
        const timeoutSeconds = parseBoundedInteger(parsed.flags, "timeout-seconds", 30, 900);
        await runOAuthOnboarding({
          port: parseBoundedInteger(parsed.flags, "port", 0, 65_535),
          redirectUri: flagString(parsed.flags, "redirect-uri"),
          timeoutMs: timeoutSeconds === undefined ? undefined : timeoutSeconds * 1000,
          noBrowser: hasFlag(parsed.flags, "no-browser"),
        });
        console.log("Google Search Console OAuth grant stored securely in System Vault.");
        return;
      }
      default:
        throw new CliError(`unknown command: ${command}\n\n${usage()}`);
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`Error: ${message}`);
    process.exitCode = error instanceof CliError ? error.exitCode : 1;
  }
}

if (import.meta.main) void main();

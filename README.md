# gsc-cli

Read-only Google Search Console reporting CLI and OAuth onboarding tool.

## Install

Requires [Bun](https://bun.sh/). From a checkout of this repository:

```bash
bun install
```

The executable is `./bin/gsc-cli`. It runs TypeScript directly with Bun; no
build step is required.

## Commands

All commands accept `help` to display the built-in usage text.

```text
./bin/gsc-cli properties [--json]
./bin/gsc-cli verify <property> [--json]
./bin/gsc-cli clicks <property> --days N [--end-date YYYY-MM-DD] [--json]
./bin/gsc-cli onboard --confirm [options]
./bin/gsc-cli help
```

- `properties` lists accessible properties and their permission levels.
- `verify` confirms one exact, accessible property string.
- `clicks` reports aggregate web clicks for 1–365 inclusive days. It does not
  request query, page, or dimension data. `--end-date` defaults to today.
- `onboard` performs offline OAuth consent using a loopback callback and stores
  the resulting refresh token through the configured credential store. It
  requires `--confirm`.
- `help` prints command details and OAuth callback guidance.

The `--json` option emits machine-readable output for reporting commands.
OAuth also supports `--port`, `--redirect-uri`, `--timeout-seconds`, and
`--no-browser`; see `./bin/gsc-cli help` for their constraints.

## Environment and OAuth onboarding

For reporting, provide these environment variables through your secret manager
or process supervisor. Do not commit a `.env` file or put secret values in
command arguments:

- `GOOGLE_SEARCH_CONSOLE_CLIENT_ID`
- `GOOGLE_SEARCH_CONSOLE_CLIENT_SECRET`
- `GOOGLE_SEARCH_CONSOLE_REFRESH_TOKEN`
- `GOOGLE_SEARCH_CONSOLE_TOKEN_URI` (optional; defaults to Google's HTTPS token
  endpoint)

For onboarding, provide the client ID and secret plus exactly one destination
for the new refresh token:

- `GOOGLE_SEARCH_CONSOLE_CREDENTIAL_COMMAND` (optional; executable path that
  receives the token on stdin)
- `GOOGLE_SEARCH_CONSOLE_REFRESH_TOKEN_FILE` (optional; path written with the
  token and a trailing newline)

The command and file options are mutually exclusive. No credential destination
is selected by default.

The OAuth client must be authorized with the
`https://www.googleapis.com/auth/webmasters.readonly` scope. To onboard a new
refresh token, provide only the client ID, client secret, and optional token URI
to the onboarding process, then run:

```bash
./bin/gsc-cli onboard --confirm
```

Onboarding uses state and PKCE, binds a local loopback callback, and never
prints the provider consent URL. If a browser cannot be opened, use the local
helper URL it prints. Desktop OAuth clients support this flow. For a web OAuth
client, register the exact loopback callback URI and pass it with
`--redirect-uri`; use `--port` when a fixed local port is required.

## Check

Run the type check and test suite with:

```bash
bun run check
```

Individual commands are available as `bun run typecheck` and `bun run test`.

## License

MIT. See [LICENSE](LICENSE).

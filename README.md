# gsc-cli

Google Search Console reporting CLI and API client

## Install

## Use

## License

MIT.
# gsc-cli

A TypeScript CLI and client for Google Search Console reporting and OAuth onboarding.

## Install

Requires Bun. Clone this repository, run `bun install`, then run `bun run check`.

## Use

The executable is `./bin/gsc-cli`. The default invocation is:

```bash
system-vault run google-search-console -- ./bin/gsc-cli help
```

Commands: Run `./bin/gsc-cli help` for property listing, query reporting, and OAuth options. Reporting uses explicit properties, date windows, dimensions, and row limits.

## Environment

Credentials are read only from environment variables. Inject them with your organization's secret broker; never commit a `.env` file or put secret values in arguments.

`GOOGLE_SEARCH_CONSOLE_CLIENT_ID`, `GOOGLE_SEARCH_CONSOLE_CLIENT_SECRET`, `GOOGLE_SEARCH_CONSOLE_REFRESH_TOKEN`, optional `GOOGLE_SEARCH_CONSOLE_TOKEN_URI`.

## License

MIT. See [LICENSE](LICENSE).

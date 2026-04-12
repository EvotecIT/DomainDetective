# Subdomains (Discovery)

## What this check does

The Subdomains check discovers hostnames for a target domain using certificate transparency (CT) observations. It can optionally verify whether each discovered hostname still resolves in DNS (bounded and concurrent).

Use this to build an inventory of potential attack surface (historical, stale, or unintended subdomains) and to prioritize cleanup or monitoring.

## Data captured

- Query status: success/failure + reason (when available)
- CT observation counts: total rows observed, first/last seen timestamps (UTC)
- Issuer diversity: issuer counts (best-effort, based on CT payload)
- Discovered subdomains:
  - `Name`
  - `FirstSeenUtc` / `LastSeenUtc` (when provided by CT)
  - `ResolutionStatus` (`Unknown`, `Resolves`, `DoesNotResolve`, `QueryFailed`)

## Controls / tuning

The primary implementation lives in `DomainDetective.SubdomainsAnalysis`.

- `VerifyStillResolves` (default: `true`): enables DNS verification.
- `MaxCtRowsToProcess` (default: `10_000`): caps processed CT rows (large domains).
- `MaxSubdomains` (default: `10_000`): caps distinct discovered subdomains retained.
- `MaxResolutionChecks` (default: `500`): caps the number of hostnames verified for DNS resolution.
- `ResolutionConcurrency` (default: `20`): limits concurrent DNS checks.
- `CrtShUrlTemplate`: CT query URL template (override for self-hosted or alternative endpoints).
- `EnableNativeCtLogSource`: enables direct RFC6962 CT log polling (`/ct/v1/get-sth`, `/ct/v1/get-entries`).
- `NativeCtLogOnly`: disables `crt.sh` / Cert Spotter fallback and uses only native CT logs.
- `NativeCtLogListUrl` / `NativeCtLogUrls`: CT log list URL or explicit CT log endpoints.
- `NativeCtCursorStatePath`: optional per-domain/per-log cursor persistence path for incremental polling.
- `QueryOverride`: test/offline hook to supply CT JSON directly.

DNS verification uses `DomainDetective.DnsConfiguration` and supports overriding DNS queries via `DnsConfiguration.QueryDnsOverride` (tests/offline).

## Output surfaces

- HTML report: renders a “Subdomains (Discovery)” section with summary, findings, evidence tables, and references.
- Word report: renders a “Subdomains” section (summary + findings + evidence).
- Excel report (net8.0): renders a “Subdomains (Discovery)” block (summary + issuer/subdomain tables).

## Notes and limitations

- CT-derived hostnames are an observation set, not a complete inventory (and may include historical names).
- DNS verification is intentionally bounded for performance; entries beyond the cap remain `Unknown`.
- IDN normalization is applied; invalid hostnames are skipped.
- Very large CT result sets may be capped (`ResultsCapped = true`) to protect performance; raise caps cautiously if needed.
- Cert Spotter exact-host and full-domain expansion queries have different budgets. See [CT_PROVIDERS.MD](CT_PROVIDERS.MD) before scheduling service-scale expansion.

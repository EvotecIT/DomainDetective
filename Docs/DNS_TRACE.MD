# DNS Trace

## What this check does

The DNS Trace check performs an authoritative-style, hop-by-hop trace starting from root servers and following referrals until it reaches an authoritative answer (or a clear failure mode).

It captures a per-query step log so you can see:

- Which servers were queried at each depth
- Response codes and section counts (Answer/Authority/Additional)
- Delegation/referral targets (next servers) when present
- CNAME chasing when the requested type is not directly answered

This is designed for explainability and debugging of DNS behavior.

## Controls / tuning

The primary implementation lives in `DomainDetective.DnsTraceAnalysis`.

- `RecordTypesToTrace` (default: `A`, `AAAA`)
- `IncludeIpv6RootServers` (default: `false`)
- `MaxDepth` (default: `12`)
- `MaxServersPerDepth` (default: `4`)
- `MaxTotalSteps` (default: `250`)
- `MaxCnameHops` (default: `5`)
- `TimeoutMilliseconds` (default: `2500`)
- `QueryOverride` (test/offline hook returning a `DnsClientX.DnsResponse`)

DNS queries use `DomainDetective.DnsConfiguration` and can be influenced via:

- `DnsConfiguration.DnsEndpoint` / `DnsConfiguration.DnsSelectionStrategy`
- `DnsConfiguration.DnsEndpoints` + `DnsConfiguration.MultiResolverStrategy`

## Output surfaces

- HTML report: “DNS Trace” section with summary, trace results, and a capped step log table.
- Word report: “DNS Trace” section with summary, trace results, and a capped step log table.
- Excel report (net8.0): “DNS Trace” block with summary, trace results, and a capped step log table.

## Notes and limitations

- This is a best-effort trace for diagnostics; it is not intended to replace a full recursive resolver implementation.
- Row counts are capped to keep output sizes predictable (`MaxTotalSteps` and renderer caps).
- Referral follow uses glue (Additional A/AAAA) when present; otherwise it attempts an internal A lookup for the first NS host in Authority.


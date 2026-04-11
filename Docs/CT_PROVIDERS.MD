# Certificate Transparency Providers

DomainDetective has several CT paths. They do not have the same cost, coverage, or reliability, so services should pick a provider based on the operation instead of treating "CT" as a single generic source.

## Recommended Service Usage

Use DomainDetective entry points first:

| Scenario | PowerShell | CLI | C# |
| --- | --- | --- | --- |
| Live certificate inventory with optional CT evidence | `Invoke-DDCertificateInventory` | `DomainDetective.CLI CertificateInventoryCapture` | `CertificateInventoryCapture.CaptureAsync(...)` |
| Add CT-observed subdomains to the monitored target set | `Invoke-DDCertificateInventory -IncludeCtSubdomains` | `CertificateInventoryCapture --include-ct-subdomains` | `CertificateInventoryCaptureOptions.IncludeCtDiscoveredSubdomains = true` |
| Use native CT logs instead of passive public APIs | `Invoke-DDCertificateInventory -EnableNativeCtLogSubdomains -NativeCtLogOnly` | `CertificateInventoryCapture --enable-native-ct-logs --native-ct-log-only` | `CertificateInventoryCaptureOptions.EnableNativeCtLogSubdomainSource = true; NativeCtLogOnly = true` |
| Reuse existing provider planning in a service | Use the cmdlet until a dedicated CT cmdlet exists | Use the CLI until a dedicated CT command exists | `CtIngestionPlanner`, `CtCertificateQuery`, `ICtCertificateTransparencyProvider` |

Use Cert Spotter through the DomainDetective CT provider abstractions for current/unexpired certificate monitoring when you have an API key and a configured budget. Use exact-host queries for monitored assets, and reserve full-domain queries for controlled subdomain expansion.

Use crt.sh PostgreSQL as a best-effort historical/backfill source. The public database can return full DER certificates and historical rows, but it is a shared PostgreSQL replica and may cancel even small queries under load.

Use crt.sh HTTPS only through the existing DomainDetective passive CT fallback or for manual maintainer investigation. It can hydrate a certificate by ID (`?d=`), but the public HTTPS service is slow and frequently rate-limited or unavailable.

Use native CT logs for cursor-based ingestion into a local index. Direct logs are not a good ad-hoc "find everything for this domain" API because logs are append-only streams, not domain indexes.

## Provider Matrix

| Provider | Best For | Full Certificate Material | Notes |
| --- | --- | --- | --- |
| Cert Spotter | Current exact host | Yes, via `expand=cert_der` | Separate exact/full-domain budgets |
| Cert Spotter | Subdomain expansion | Yes, if expanded | Full-domain budget is small |
| crt.sh PostgreSQL (SQL FTS) | Historical backfill | Yes, certificate table DER | PostgreSQL interface; use certificate-table FTS query style |
| crt.sh HTTPS | Fallback hydration | Yes, via `?d=<id>` | Slow, 503s are common |
| Native CT logs | Local ingestion | Yes, from log entries | Needs cursors/local index |

## Representative Smoke-Test Observations

These observations came from an ad-hoc live smoke test against a representative domain. Treat them as directional evidence for service design, not as provider SLAs.

| Path | Observed Time | Observed Result | Service Guidance |
| --- | --- | --- | --- |
| Live TLS probe for the apex host | 118 ms | Returned the live Google Trust Services WE1 certificate, expiring 2026-07-04 | Best current-state source when the endpoint is reachable |
| Cert Spotter exact-host DER query | 1.62 s | Returned 7 rows, all with DER; latest CT certificate matched the live certificate and expired 2026-07-04 | Good for latest known public issuance when endpoint reachability is not guaranteed |
| Cert Spotter domain expansion through DomainDetective-equivalent request | 354 ms | Processed 7 CT observations and produced 3 unique DNS names; expansion did not include full DER because it used `expand=dns_names` | Good expansion source; follow with exact-host queries for full latest certificates |
| crt.sh HTTPS exact query with DER hydration | 3.23 s | Returned 495 JSON rows and hydrated certificate ID `25432709504`; latest certificate matched the live certificate | Works when healthy, but still treat as fallback because public rate limits and 502/503s are common |
| crt.sh HTTPS wildcard expansion | 3.28 s | Returned 495 JSON rows and 51 unique names | Useful for manual checks, but not preferred for service-scale expansion |
| crt.sh PostgreSQL exact FTS | 4.15 s | Returned 5 typed row mappings from the `certificate` table; first row had 932 DER bytes and matched the latest live/CT certificate | Best-effort historical/backfill path with strict timeout and cooldown |
| crt.sh PostgreSQL domain FTS sample | 1.86 s | Returned a capped 20-name sample from certificate-table FTS | Useful for SQL-backed backfill/analysis, not a separate provider from crt.sh PostgreSQL |
| Native CT limited tail fetch | 1.24 s | Fetched a small tail range from one Google Argon CT log; this was not a domain lookup and did not decode certificates | Useful only with persisted cursors/local indexing, not ad-hoc domain lookup |

## Cert Spotter Budgets

The default `CtProviderProfiles.CreateCertSpotter()` profile models the public Small CT Search API limits as separate budgets:

| Budget | Default Limit |
| --- | --- |
| Single-hostname | 100 / hour |
| Full-domain | 10 / hour |
| Requests per minute | 75 / minute |
| Requests per second | 5 / second |
| Query timeout | 15 seconds |

Single-hostname means `include_subdomains=false`. Use it for `GetLatestCertificate` on a monitored asset such as `www.example.com`.

Full-domain means `include_subdomains=true`. Use it for `DiscoverSubdomains` or domain-tree refreshes such as expanding `example.com` into observed names.

Only add `expand=cert_der` to full-domain expansion when the caller deliberately wants to spend the full-domain budget on certificate hydration during discovery.

## Query API Shape

Use the `CtCertificateQuery` factories when building service workflows. They keep the service intent visible without changing provider implementations:

| Service Task | Query Factory | Default Operation | Full Certificate Default |
| --- | --- | --- | --- |
| Latest known certificate for one monitored host | `CtCertificateQuery.ForExactHostLatest(host)` | `GetLatestCertificate` | Yes |
| Historical certificates for one monitored host | `CtCertificateQuery.ForExactHostHistory(host)` | `GetCertificateHistory` | Yes |
| Expand one domain into CT-observed names | `CtCertificateQuery.ForDomainExpansion(domain)` | `DiscoverSubdomains` | No |
| Query certificate material across a domain tree | `CtCertificateQuery.ForDomainTreeCertificates(domain)` | `GetDomainTreeCertificates` | Yes |

Use `ICtCertificateTransparencyProvider.QueryPagesAsync(...)` for provider calls that may return continuation tokens. The helper carries the provider runtime state forward and stops when the provider reports no more pages, returns an empty token, repeats the same token, or reaches the caller's `maxPages` safety cap.

For DD Next ingestion, the safer default is a two-phase flow: run `ForDomainExpansion(domain)` to discover names, then enqueue `ForExactHostLatest(host)` for each accepted host. Only use `ForDomainTreeCertificates(domain)` when the provider is explicitly configured for broad historical collection and the caller expects the larger budget impact.

## Provider HTTP Shape

This section is for maintainers implementing or debugging providers. Consumer code should use DomainDetective cmdlets, CLI commands, or C# APIs rather than constructing provider URLs directly.

For Cert Spotter exact-host full certificate queries, the provider implementation should build a request equivalent to:

```text
https://api.certspotter.com/v1/issuances?domain=<host>&include_subdomains=false&match_wildcards=true&expand=dns_names&expand=issuer&expand=cert_der
```

For controlled Cert Spotter domain expansion, the provider implementation should build a request equivalent to:

```text
https://api.certspotter.com/v1/issuances?domain=<domain>&include_subdomains=true&expand=dns_names
```

## crt.sh SQL FTS

crt.sh SQL FTS is not a separate provider from crt.sh PostgreSQL. It is the supported query style to use through the public crt.sh PostgreSQL interface. The FTS part means the query searches the full-text index exposed by `identities(c.certificate)` on the `certificate` table:

```sql
WHERE identities(c.certificate) @@ plainto_tsquery('simple', @host)
```

Do not query `certificate_identity` for new code. The public crt.sh database reports that `certificate_identity` has been superseded by the full-text search index on `certificate`.

DomainDetective's crt.sh PostgreSQL metadata provider uses the supported FTS path and tests assert that `certificate_identity` is not referenced. Keep future `DomainDetective.CtSql` implementation on that path unless crt.sh publishes a new supported schema.

Current typed status: `DomainDetective.CtSql` registers a DbaClientX-backed crt.sh PostgreSQL provider through `DomainDetectiveCtSqlRegistration.Register()`. The base `DomainDetective` package keeps the CT capture options and SQL-shape helpers, but no longer carries the PostgreSQL dependency. The provider returns DomainDetective objects such as `SubdomainDiscoveryEntry`; the broader `CtCertificateQuery` / `CtCertificateQueryResult` provider implementation is still planned for the dedicated end-to-end CT query surface.

## DD Next Planning Notes

Model provider state per provider and per budget type. A Cert Spotter exact-host queue should not consume the same schedule as Cert Spotter full-domain expansion.

Persist continuation tokens such as Cert Spotter `after` IDs separately from domain/subdomain records. The service should be able to resume a paged query without re-querying the first page.

Store certificates by fingerprint, preferably SHA-256 DER fingerprint, and link observations from live TLS, Cert Spotter, crt.sh SQL, and native CT back to the same certificate row.

Treat latest/current as a derived view, not as the only stored fact. CT latest and live TLS current can legitimately differ because live TLS requires network connectivity while CT observes public issuance.

Keep crt.sh SQL behind explicit historical/backfill configuration. If PostgreSQL returns recovery-conflict, timeout, or transient-load errors, cool the provider down and continue the monitoring cycle with other providers.

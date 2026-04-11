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
| crt.sh SQL FTS | Historical backfill | Yes, certificate table DER | Shared public DB is fragile |
| crt.sh HTTPS | Fallback hydration | Yes, via `?d=<id>` | Slow, 503s are common |
| Native CT logs | Local ingestion | Yes, from log entries | Needs cursors/local index |

## eurofins.com Smoke-Test Observations

These observations came from an ad-hoc live smoke test against `eurofins.com`. Treat them as directional evidence for service design, not as provider SLAs.

| Path | Observed Time | Observed Result | Service Guidance |
| --- | --- | --- | --- |
| Live TLS probe for `eurofins.com` | 468 ms | Returned the live Amazon RSA 2048 M02 certificate, expiring 2026-06-11 | Best current-state source when the endpoint is reachable |
| Cert Spotter exact-host DER query | 514 ms | Returned 4 rows, latest unexpired CT certificate expiring 2026-05-25 | Good for latest known public issuance when endpoint reachability is not guaranteed |
| Cert Spotter domain expansion through DomainDetective | 2.37 s | Processed 100 CT observations and produced 397 subdomains; expansion did not include full DER because it used `expand=dns_names` | Good expansion source; follow with exact-host queries for full latest certificates |
| crt.sh HTTPS exact query with DER hydration | 74.8 s | Eventually returned certificate material, but was much slower than Cert Spotter | Fallback/manual path only |
| crt.sh HTTPS expansion through DomainDetective | 40 s | Failed with HTTP 503 | Do not rely on this for service-scale expansion |
| Native CT limited tail scan | 13 s | No `eurofins.com` entries found in the small scanned window | Useful only with persisted cursors/local indexing, not ad-hoc domain lookup |
| crt.sh PostgreSQL public DB rich query | Not comparable | DomainDetective-style query was canceled by the public replica due recovery conflict; simpler FTS probes against `certificate` worked | Best-effort historical/backfill path with strict timeout and cooldown |

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

crt.sh SQL FTS is the supported PostgreSQL query style against the public crt.sh database. It is still "crt.sh SQL"; the FTS part means the query searches the full-text index exposed by `identities(c.certificate)` on the `certificate` table:

```sql
WHERE identities(c.certificate) @@ plainto_tsquery('simple', @host)
```

Do not query `certificate_identity` for new code. The public crt.sh database reports that `certificate_identity` has been superseded by the full-text search index on `certificate`.

DomainDetective's current crt.sh PostgreSQL metadata queries already use the supported FTS path and tests assert that `certificate_identity` is not referenced. Keep future `DomainDetective.CtSql` implementation on that path unless crt.sh publishes a new supported schema.

Current typed status: the in-tree fallback uses parameterized Npgsql commands, typed array parameters for domain batches, an internal `CrtShPostgreSqlExactMetadataRow` mapping type, and returns DomainDetective objects such as `SubdomainDiscoveryEntry`. It is not yet a fully typed public `DomainDetective.CtSql` provider surface: the SQL is still a handwritten string in the base package, the public `DomainDetective.CtSql` package is a registration shell, and the CT SQL provider still needs to move into that package with a typed `CtCertificateQuery` / `CtCertificateQueryResult` implementation.

## DD Next Planning Notes

Model provider state per provider and per budget type. A Cert Spotter exact-host queue should not consume the same schedule as Cert Spotter full-domain expansion.

Persist continuation tokens such as Cert Spotter `after` IDs separately from domain/subdomain records. The service should be able to resume a paged query without re-querying the first page.

Store certificates by fingerprint, preferably SHA-256 DER fingerprint, and link observations from live TLS, Cert Spotter, crt.sh SQL, and native CT back to the same certificate row.

Treat latest/current as a derived view, not as the only stored fact. CT latest and live TLS current can legitimately differ because live TLS requires network connectivity while CT observes public issuance.

Keep crt.sh SQL behind explicit historical/backfill configuration. If PostgreSQL returns recovery-conflict, timeout, or transient-load errors, cool the provider down and continue the monitoring cycle with other providers.

# Running domain checks efficiently

`DomainHealthCheck.Verify` shares compatible work within a domain run. Selecting HTTP, CERT, and WEBSITE reuses the HTTP and certificate analyses needed by WEBSITE. NS and DELEGATION share child nameserver discovery; delegation still obtains its separate parent evidence. A new verification performs fresh analysis rather than reusing the previous run's mutable results.

DNS queries use DnsClientX resolver reuse, response caching, and concurrent-query coalescing. The default health-check configuration enables response caching. Assigning a custom `DnsConfiguration` preserves its response-cache setting. DNSSEC validation continues through the resolver's validation and cache policy.

## Control concurrency

```csharp
using var health = new DomainHealthCheck();
var execution = new HealthCheckExecutionOptions {
    MaxParallelism = 8,
    DnsParallelism = 16
};

await health.Verify("example.com", new[] {
    HealthCheckType.HTTP,
    HealthCheckType.CERT,
    HealthCheckType.WEBSITE,
    HealthCheckType.NS,
    HealthCheckType.DELEGATION,
    HealthCheckType.DNSSEC
}, cancellationToken: cancellationToken, executionOptions: execution);
```

`MaxParallelism` limits active checks. `DnsParallelism` limits recursive DNS queries across the run, including DNSSEC and DNSBL. In `VerifyBatchAsync` and `ProcessBatchAsync`, that DNS limit is shared across admitted domains; `MaxDomainParallelism` controls the number of active domains. The recursive-query limit does not cover direct authoritative DNS probes, HTTP requests, or TLS connections, which have their own bounds.

DNSBL provider requests share at most half of the recursive-query slots, with a minimum of one. The allowance is shared across batch domains too, leaving capacity for target discovery, SPF, TTL, and other recursive checks during a large provider sweep.

Use independent health-check instances for concurrent domains. A health check contains mutable analysis state and should have one active verification at a time. Dispose health checks and batch results when their evidence is no longer needed.

Increasing concurrency helps independent queries overlap. Resolver throttling, remote latency, failed connections, and configured analysis budgets can still determine elapsed time.

## Time budgets and incomplete evidence

Caller cancellation propagates as cancellation. An internal analysis deadline retains the available evidence and marks the affected coverage incomplete. Read completion and error fields alongside the verdict: a failed probe does not establish that a feature is absent.

| Analysis | Default budgets and concurrency | Evidence to inspect |
| --- | --- | --- |
| HTTP | 30 seconds per request operation | Reachability and failure details |
| Certificate | 60 seconds overall; 5 seconds per TLS version probe; 10 seconds for CT discovery | `AnalysisComplete`, `ProtocolSupportComplete`, `LegacyProtocolSupportComplete`, `CtLookupComplete` |
| DNSSEC | 5 seconds per query; 15 seconds overall | Validation status, `MetadataQueriesComplete`, `MetadataQueryFailures` |
| DNSBL | 8 seconds overall; 2 seconds per provider query after recursive admission; 2 seconds per discovery lookup including admission | `DiscoverySucceeded`, `DiscoveryErrors`, per-record `QuerySucceeded` and `Error` |
| Sitemap | 20 seconds per HTTP probe; 60 seconds overall; 8 concurrent URL probes | `AnalysisComplete` and retained URL results |
| Typosquatting | 60 seconds overall; 8 candidate workers | `AnalysisComplete`, incomplete DNS checks and query errors |
| Static web scan | 60 seconds overall; 5 seconds for TLS; 10 seconds per RDAP lookup | `AnalysisComplete`, host TLS and DNS enrichment errors |

For example, a CT deadline can leave a successfully captured certificate and entries from an earlier CT source intact while setting `CtLookupComplete` and `AnalysisComplete` to false. `PresentInCtLogs = false` with incomplete CT coverage does not confirm absence. Likewise, a local TLS policy error or timeout leaves protocol coverage incomplete rather than proving that the server rejects that protocol.

Configure the owning analysis when a workflow needs different budgets:

```csharp
health.CertificateAnalysis.AnalysisTimeout = TimeSpan.FromSeconds(90);
health.CertificateAnalysis.CtLookupTimeout = TimeSpan.FromSeconds(20);
health.DnsConfiguration.DnsSecQueryTimeout = TimeSpan.FromSeconds(5);
health.DnsConfiguration.DnsSecAnalysisTimeout = TimeSpan.FromSeconds(20);
health.DNSBLAnalysis.AnalysisTimeout = TimeSpan.FromSeconds(12);
health.DNSBLAnalysis.DiscoveryTimeout = TimeSpan.FromSeconds(3);
```

DNSBL checks resolved targets while other discovery continues. Slow or unavailable providers can still consume its overall budget. Compare completed provider coverage and discovery errors when comparing scan times; a shorter incomplete scan is not equivalent to a completed scan.

With a single resolver slot, DNSBL caps each discovery lookup at half the remaining overall budget so that a slow address family leaves time to check an already-resolved target. An IPv6 provider's A and AAAA requests share one provider execution deadline, starting when the first request obtains recursive admission.

## HTTP transport and reference data

Anonymous HTTP posture probes reuse connections. Requests with explicit headers, cookies, proxy settings, custom handlers, or certificate-validation changes retain isolated transport. Cookies received during an anonymous request stay within that request's redirect chain.

Bundled public-suffix and HSTS data use shared immutable snapshots, reducing repeated health-check construction costs. Explicit reference-data refreshes and custom inputs retain their own load behavior.

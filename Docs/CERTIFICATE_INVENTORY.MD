# Certificate Inventory and Discovery

This guide explains how to run certificate discovery end-to-end in DomainDetective, what data is captured, where it is stored, and how to analyze it at scale.

It is designed for large enterprise portfolios (thousands of domains), where you need to answer:

- Which domains/endpoints use which certificates?
- Which CA/issuer/root signed them?
- Which services are those certificates assigned to?
- Does a certificate allow server auth, client auth, or secure email?
- Is chain/trust complete, and is the cert expiring or invalid?
- How does posture drift over time?

## Core model: live capture plus snapshot analytics

Certificate inventory has two stages:

1. Live capture (`Invoke-DDCertificateInventory` / `CertificateInventoryCapture`)
2. Snapshot analytics (`Get-DDCertificateInventory*` cmdlets / `CertificateMonitor.BuildInventory*`)

This is why the cmdlet is now named `Invoke-...` and not `Import-...`:

- `Invoke-DDCertificateInventory` actively probes endpoints and optionally enriches from CT sources.
- It can persist a snapshot to disk so you can do drift/risk/policy/reuse analytics later.

## What `CacheDirectory` means

`CacheDirectory` is the local working folder used for certificate inventory storage.

- Inventory snapshots are saved under: `<CacheDirectory>/inventory/*.json`
- If not specified, default is:
  - `Path.GetTempPath()/DomainDetective/cert-monitor`
- Use a stable path in production so history is preserved between runs.

PowerShell quick check:

```powershell
Get-DDCertificateInventorySnapshot -CacheDirectory .\cert-monitor -Latest -WithoutEntries
```

## Smart Reuse Cache (skip redundant probes)

When you run repeated captures against large portfolios, you can reuse recent endpoint results instead of probing everything every time.

- Enable with `-ReuseRecentResults`.
- Reuse window is controlled by `-RecentResultTtlHours` (default `24`).
- Optional stable-failure reuse is controlled by `-ReuseRecentFailureResults` with `-RecentFailureResultTtlHours` (default `1`).
- Near-expiry certificates are always refreshed based on `-ReprobeExpiringWithinDays` (default `14`).
- Reuse is endpoint-based (`host + port + service`).

Reuse only applies when a cached endpoint result is considered safe:

- endpoint was reachable
- certificate thumbprint exists
- certificate is not expired
- certificate is not inside the re-probe expiry window

Stable-failure reuse is narrower and intended for hot verification lanes:

- endpoint had no captured certificate
- failure was a stable connectivity outcome (for example timeout, DNS resolution failure, connection refused/reset, or TLS handshake failure)
- failure entry is still inside the shorter failure TTL window

This keeps recurring runs fast while still refreshing risky/soon-expiring endpoints.

## Discovery coverage and sources

DomainDetective combines endpoint probing and CT evidence:

| Source | What you get | Configuration |
| --- | --- | --- |
| HTTPS probing | Live leaf cert, chain, issuer/root, EKU/auth profile, validity, hostname match, protocol/service | Included by default (apex + `www`) |
| MX discovery + STARTTLS | Mail host certs from SMTP 25/587; optional IMAPS/POP3S | Default includes STARTTLS; IMAP/POP3 optional |
| Additional endpoints | Explicit app/service targets (`https://`, `smtp://`, etc.) | `-Endpoint` / `AdditionalEndpoints` |
| Native CT log polling (RFC6962) | Direct CT ingestion from trusted log operators (no crt.sh dependency) | `EnableNativeCtLogSubdomainSource`, `NativeCt*` options |
| Public CT API (`crt.sh`) | CT presence and source evidence for observed certs | Enabled by default template |
| Optional CT APIs (Shodan/Censys/custom) | Wider CT discovery source coverage | `CtProfile`, source toggles, API keys/templates |

Notes:

- `crt.sh` is used by default via `https://crt.sh/?sha256={0}&output=json`.
- `crt.sh` is public and does not require API credentials in this flow.
- For commercial sources, credentials are required (for example Shodan/Censys).
- MX hosts are often inbound-only and may not expose `587/993/995`; empty certificate fields on those rows usually indicate service not reachable on that endpoint, not parser failure.
- Null-MX and numeric-only MX artifacts are skipped during MX host extraction (so invalid targets like `smtp://0:25` are not generated).
- Endpoint probe errors are expected on large CT-expanded scans (historical/internal hosts). Use `-MaxProbeErrorWarnings` to limit warning noise.
- Use `-MaxTargets` for quick/safe test runs and `-MaxProbeStartsPerSecond` as an anti-hammer throttle.
- Use `-ReuseRecentResults` with `-RecentResultTtlHours` to skip re-probing endpoints already captured recently.
- Use `-ReuseRecentFailureResults` with `-RecentFailureResultTtlHours` when repeated verification runs are wasting time on endpoints that are consistently dead or timing out.
- `-ReprobeExpiringWithinDays` keeps near-expiry certificates fresh even when cache reuse is enabled.
- Native CT log polling supports per-domain/per-log cursor persistence (`NativeCtCursorStatePath`) to avoid reprocessing the same CT ranges.
- With multiple domains and native CT enabled, DomainDetective reuses one shared CT ingestion pass by default (`EnableNativeCtSharedIngestion = true`) and correlates discovered names to all monitored suffixes.
- Native CT polling now includes built-in retry/backoff, per-log circuit breaker, and catch-up mode for large cursor lag.
- Capture results now include `NativeCtLogDiagnostics` so you can inspect per-log ingestion state (succeeded/failed/circuit-open, lag before/after, last processed index) without opening cursor JSON.

### Capture controls quick reference

| Control | Default | Purpose |
| --- | --- | --- |
| `-MaxTargets` (`-Limit`) | `0` (unlimited) | Cap total discovered probe targets (HTTPS + mail) for test/safety runs |
| `-MaxProbeStartsPerSecond` | `0` (unlimited) | Anti-hammer throttle for probe start rate |
| `-MaxProbeErrorWarnings` | `25` | Limit verbose endpoint error warning noise |
| `-ReuseRecentResults` | Off | Reuse recent persisted endpoint results to skip redundant probes |
| `-RecentResultTtlHours` | `24` | How long cached endpoint results are eligible for reuse |
| `-ReuseRecentFailureResults` | Off | Reuse recent stable failures to avoid immediately re-probing consistently dead endpoints |
| `-RecentFailureResultTtlHours` | `1` | How long stable failure entries are eligible for reuse |
| `-ReprobeExpiringWithinDays` | `14` | Always recheck endpoints whose certs expire soon |
| `-DisableNativeCtSharedIngestion` | Off | Disable shared native CT pass and fall back to per-domain native CT ingestion |
| `-NativeCtRetryCount` | `3` | Retry transient native CT HTTP failures |
| `-NativeCtCircuitBreakerFailureThreshold` | `3` | Open per-log circuit after repeated failures |
| `-NativeCtCircuitBreakerDurationSeconds` | `600` | Pause failing CT logs before re-trying |
| `-DisableNativeCtCatchUpMode` | Off | Disable adaptive catch-up when native CT cursor lag is high |
| `-NativeCtCatchUpLagThreshold` | `50000` | Cursor lag threshold that enables catch-up |
| `-NativeCtCatchUpMaxEntriesPerLog` | `20000` | Expanded per-log entry cap in catch-up mode |
| `-NativeCtCatchUpBatchSize` | `1024` | Expanded batch size in catch-up mode |

## PowerShell end-to-end examples

### Inventory-first runbook (recommended starting point)

If your first goal is a useful certificate list (endpoint inventory + unique cert map), run:

```powershell
.\Module\Examples\Example.CertificateInventory.InventoryFirst.ps1
```

It will:

- Capture inventory from your seed domains.
- Expand scan scope with CT-discovered subdomains.
- Persist snapshots in `cert-monitor`.
- Export:
  - `artifacts/certificate-endpoint-inventory.csv`
  - `artifacts/certificate-unique-summary.csv`
  - `artifacts/certificate-endpoint-changes.csv`

Use this as your base workflow, then schedule it (Task Scheduler/CI/Service) for continuous monitoring.

### 1. Capture a snapshot from domains

```powershell
Import-Module .\Module\DomainDetective.psd1 -Force

$domains = @(
    'evotec.xyz'
    'evotec.pl'
    'microsoft.com'
    'google.com'
    'eurofins.com'
    'abb.com'
)

$capture = Invoke-DDCertificateInventory `
    -DomainName $domains `
    -CacheDirectory .\cert-monitor `
    -ReuseRecentResults `
    -RecentResultTtlHours 24 `
    -ReuseRecentFailureResults `
    -RecentFailureResultTtlHours 1 `
    -ReprobeExpiringWithinDays 14 `
    -CtProfile Extended `
    -IncludeCtSubdomains `
    -VerifyCtSubdomains `
    -EnableShodanCtSource `
    -ShodanApiKeyEnv SHODAN_API_KEY `
    -IncludeImapTls `
    -IncludePop3Tls `
    -MaxTargets 300 `
    -MaxProbeStartsPerSecond 20 `
    -MaxParallelism 24 `
    -DiscoveryParallelism 32 `
    -MaxProbeErrorWarnings 25 `
    -Verbose

$capture | Format-List CapturedAtUtc,SnapshotPath,DomainCount,MxHostCount,EntryCount,ValidCount,ExpiredCount,FailedCount
```

Useful run telemetry now returned directly on the capture result:

- `ReusedRecentEntryCount`, `ReusedRecentHttpsCount`, `ReusedRecentMailCount`
- `ReusedRecentFailureEntryCount`, `ReusedRecentFailureHttpsCount`, `ReusedRecentFailureMailCount`
- `ProbedHttpsCount`, `ProbedMailCount`
- `CtPromotedHttpsCount`, `CtSkippedHttpsPromotionCount`
- `CtSkippedUnresolvedHttpsPromotionCount`, `CtSkippedLowConfidenceHttpsPromotionCount`, `CtSkippedDuplicateHttpsPromotionCount`
- `MxPromotedHttpsCount`, `MxPromotedMailCount`
- `MxInvalidArtifactCount`, `MxDuplicateHostCount`, `MxSkippedDuplicateHttpsPromotionCount`
- `HttpsTargetCountBeforeLimit`, `MailTargetCountBeforeLimit`
- `HttpsTargetCountDroppedByLimit`, `MailTargetCountDroppedByLimit`
- `TargetOriginCounts`, `CaptureDispositionCounts`
- `TargetDecisionDiagnostics`
- `TargetDecisionSummary`

Each snapshot entry now also carries per-endpoint provenance:

- `TargetOrigins`: why the endpoint was targeted in this run (`seed-apex`, `seed-exact-host`, `seed-www`, `ct-discovery`, `mx-https`, `mx-mail`, `additional-endpoint`)
- `CaptureDisposition`: how the endpoint entered the result for this run (`live-probe`, `reused-recent-success`, `reused-recent-stable-failure`)

The capture result and persisted snapshot also include structured `TargetDecisionDiagnostics`
for targets that were rejected or pruned, including:

- invalid additional endpoints
- unsupported additional-endpoint schemes
- specific HTTPS/mail targets pruned by `MaxTargets`

`TargetDecisionSummary` groups those raw events by `Stage` + `Action` + `Reason` and includes:

- `Severity`
- `RecommendedAction`
- `Count`
- `ExampleTargets`
- `ExampleServices`
- merged `TargetOrigins`

When the CLI writes `--csv-path` or `--ndjson-path`, it also emits a companion
target-decision summary export beside the main file:

- `capture.csv` -> `capture.target-decision-summary.csv`
- `capture.ndjson` -> `capture.target-decision-summary.ndjson`

Those companion exports keep the entry-level output unchanged while projecting the
grouped target-decision buckets with severity and recommended action hints. The CLI
table output also shows warning-level decision buckets first, and
`--fail-on-warning-target-decisions` returns exit code `2` when warning-level target
decisions are present so automation can treat configuration-quality issues as
actionable failures.

The PowerShell cmdlet supports the same strict-mode behavior via
`-FailOnWarningTargetDecisions`, which emits warning records for each warning-level
target-decision bucket and then throws a terminating error when strict mode is
requested.

For large domains where you want CT-seen hostnames added to scan scope:

```powershell
Invoke-DDCertificateInventory `
    -DomainName eurofins.com `
    -CacheDirectory .\cert-monitor `
    -IncludeCtSubdomains `
    -ReuseRecentResults `
    -RecentResultTtlHours 24 `
    -ReuseRecentFailureResults `
    -RecentFailureResultTtlHours 1 `
    -MaxTargets 150 `
    -MaxProbeStartsPerSecond 20 `
    -MaxProbeErrorWarnings 10 `
    -MaxCtSubdomainsPerDomain 5000 `
    -MaxCtRowsPerDomain 20000
```

Direct native CT ingestion (without `crt.sh`/Cert Spotter):

```powershell
Invoke-DDCertificateInventory `
    -DomainName eurofins.com,evotec.pl,evotec.xyz `
    -CacheDirectory .\cert-monitor `
    -IncludeCtSubdomains `
    -EnableNativeCtLogSubdomains `
    -NativeCtLogOnly `
    -NativeCtInitialBackfillEntriesPerLog 5000 `
    -NativeCtMaxLogs 12 `
    -NativeCtMaxEntriesPerLog 2000 `
    -NativeCtRetryCount 3 `
    -NativeCtCircuitBreakerFailureThreshold 3 `
    -NativeCtCircuitBreakerDurationSeconds 600 `
    -NativeCtCatchUpLagThreshold 50000 `
    -NativeCtCatchUpMaxEntriesPerLog 20000 `
    -NativeCtCatchUpBatchSize 1024 `
    -NativeCtCursorStatePath .\cert-monitor\inventory\ct-native-cursor.json `
    -MaxTargets 250 `
    -MaxProbeStartsPerSecond 20 `
    -Verbose
```

CLI equivalent:

```bash
DomainDetective.CLI CertificateInventoryCapture eurofins.com \
  --include-ct-subdomains \
  --verify-ct-subdomains \
  --reuse-recent-results \
  --recent-result-ttl-hours 24 \
  --reuse-recent-failures \
  --recent-failure-result-ttl-hours 1 \
  --reprobe-expiring-within-days 14 \
  --max-targets 150 \
  --max-probe-starts-per-second 20 \
  --ct-max-subdomains-per-domain 5000 \
  --ct-max-rows-per-domain 20000
```

### 2. Read raw snapshots (metadata or full entries)

```powershell
# Latest full snapshot
Get-DDCertificateInventorySnapshot -CacheDirectory .\cert-monitor -Latest

# Last 7 days, metadata only
Get-DDCertificateInventorySnapshot `
    -CacheDirectory .\cert-monitor `
    -SinceUtc (Get-Date).ToUniversalTime().AddDays(-7) `
    -WithoutEntries
```

### 3. Summary and focused queries

```powershell
Get-DDCertificateInventorySummary `
    -CacheDirectory .\cert-monitor `
    -SinceUtc (Get-Date).ToUniversalTime().AddDays(-30)

# Find likely client-auth usage (mTLS candidates)
Get-DDCertificateInventoryQuery `
    -CacheDirectory .\cert-monitor `
    -LatestOnly `
    -ClientAuthOnly `
    -MaxResults 2000

# Find certs expiring in 30 days
Get-DDCertificateInventoryQuery `
    -CacheDirectory .\cert-monitor `
    -LatestOnly `
    -ExpiringWithinDays 30 `
    -MaxResults 5000
```

### 4. Risk, drift, diff, reuse, policy

```powershell
Get-DDCertificateInventoryRisk `
    -CacheDirectory .\cert-monitor `
    -SinceUtc (Get-Date).ToUniversalTime().AddDays(-30) `
    -MinimumSeverity Medium

Get-DDCertificateInventoryDrift `
    -CacheDirectory .\cert-monitor `
    -SinceUtc (Get-Date).ToUniversalTime().AddDays(-14) `
    -ChangedOnly

Get-DDCertificateInventoryDiff -CacheDirectory .\cert-monitor

Get-DDCertificateInventoryReuse `
    -CacheDirectory .\cert-monitor `
    -SinceUtc (Get-Date).ToUniversalTime().AddDays(-30)

Get-DDCertificateInventoryPolicy `
    -CacheDirectory .\cert-monitor `
    -BaselineProfile Balanced

Get-DDCertificateInventoryPolicyDrift `
    -CacheDirectory .\cert-monitor `
    -ChangedOnly
```

### 5. Basic alerting pattern (Cloudflare-style workflow, self-hosted)

```powershell
# Scheduled run (for example every 6h)
$null = Invoke-DDCertificateInventory -DomainName (Get-Content .\domains.txt) -CacheDirectory .\cert-monitor

# Compare latest two snapshots and notify on added/changed endpoints
$diff = Get-DDCertificateInventoryDiff -CacheDirectory .\cert-monitor -MaxEndpoints 5000
$changes = $diff.Endpoints | Where-Object { $_.Status -in @('Added', 'Changed', 'Removed') }

if ($changes.Count -gt 0) {
    $changes | Select-Object Host,Port,Status,CurrentIssuer,CurrentThumbprint,CurrentNotAfterUtc |
        Export-Csv -Path .\artifacts\cert-changes.csv -NoTypeInformation -Encoding UTF8
    # Send mail/Teams/Slack here using your notification tooling
}
```

## C# end-to-end examples

### 1. Capture inventory snapshot

```csharp
using DnsClientX;
using DomainDetective;

var domains = new[] { "evotec.xyz", "evotec.pl", "microsoft.com", "google.com" };

var options = new CertificateInventoryCaptureOptions {
    CacheDirectory = @".\cert-monitor",
    DnsEndpoint = DnsEndpoint.System,
    ReuseRecentSnapshotEntries = true,
    RecentSnapshotTtl = TimeSpan.FromHours(24),
    ReuseRecentFailureSnapshotEntries = true,
    RecentFailureSnapshotTtl = TimeSpan.FromHours(1),
    ReprobeExpiringWithinDays = 14,
    CtProfile = CertificateCtEnrichmentProfile.Extended,
    EnableShodanCtSource = true,
    ShodanApiKey = Environment.GetEnvironmentVariable("SHODAN_API_KEY"),
    IncludeImapTls = true,
    IncludePop3Tls = true,
    EnableNativeCtLogSubdomainSource = true,
    NativeCtLogOnly = true,
    NativeCtInitialBackfillEntriesPerLog = 5000,
    NativeCtMaxLogs = 12,
    NativeCtMaxEntriesPerLog = 2000,
    NativeCtRetryCount = 3,
    NativeCtCircuitBreakerFailureThreshold = 3,
    NativeCtCircuitBreakerDuration = TimeSpan.FromMinutes(10),
    NativeCtCatchUpLagThreshold = 50_000,
    NativeCtCatchUpMaxEntriesPerLog = 20_000,
    NativeCtCatchUpBatchSize = 1_024,
    NativeCtCursorStatePath = @".\cert-monitor\inventory\ct-native-cursor.json",
    MaxParallelism = 24,
    DiscoveryParallelism = 32,
    PersistSnapshot = true
};

var capture = new CertificateInventoryCapture();
var result = await capture.CaptureAsync(domains, options, new InternalLogger(isVerbose: true));

Console.WriteLine($"Snapshot: {result.SnapshotPath}");
Console.WriteLine($"Entries : {result.EntryCount}");
```

### 2. Query and summarize persisted inventory

```csharp
using DomainDetective;

var monitor = new CertificateMonitor {
    CacheDirectory = @".\cert-monitor",
    PersistInventorySnapshots = false
};

var summary = monitor.BuildInventorySummary(
    sinceUtc: DateTimeOffset.UtcNow.AddDays(-30),
    expiringWithinDays: 30,
    maxExpiringEndpoints: 500);

var query = new CertificateInventoryQuery {
    SinceUtc = DateTimeOffset.UtcNow.AddDays(-30),
    LatestPerEndpointOnly = true,
    AllowsClientAuthOnly = true,
    MaxResults = 2000
};

var clientAuth = monitor.QueryInventoryEntries(query);
Console.WriteLine($"Matched entries: {clientAuth.MatchedEntryCount}");
```

### 3. Risk, drift, reuse, diff, policy

```csharp
var risk = monitor.BuildInventoryRisk(
    sinceUtc: DateTimeOffset.UtcNow.AddDays(-30),
    minimumSeverity: "Medium",
    maxEndpoints: 1000);

var drift = monitor.BuildInventoryDrift(
    sinceUtc: DateTimeOffset.UtcNow.AddDays(-14),
    changedOnly: true,
    maxEndpoints: 1000);

var diff = monitor.BuildInventoryDiff(maxEndpoints: 2000);

var reuse = monitor.BuildInventoryReuse(
    sinceUtc: DateTimeOffset.UtcNow.AddDays(-30),
    includeSingleEndpointCertificates: false);

var policy = monitor.BuildInventoryPolicy(
    sinceUtc: DateTimeOffset.UtcNow.AddDays(-30),
    baselineProfile: "Balanced");
```

### 4. Policy overrides

`CertificateInventoryPolicyOverrides.Load(...)` supports organization-specific suppressions and profile overrides.

Example `policy-overrides.json`:

```json
{
  "version": 1,
  "defaults": {
    "baselineProfile": "Balanced",
    "suppressViolationCodes": []
  },
  "rules": [
    {
      "name": "Legacy mail gateway",
      "match": {
        "hostSuffixes": [ "legacy-gateway.example.com" ],
        "services": [ "SMTP-STARTTLS" ],
        "ports": [ 25, 587 ]
      },
      "action": {
        "baselineProfile": "Legacy",
        "suppressViolationCodes": [
          "Policy.Certificate.Reuse.CrossService"
        ]
      }
    }
  ]
}
```

Use it from C#:

```csharp
var overrides = CertificateInventoryPolicyOverrides.Load(@".\policy-overrides.json");
var policy = monitor.BuildInventoryPolicy(
    sinceUtc: DateTimeOffset.UtcNow.AddDays(-30),
    baselineProfile: "Balanced",
    policyOverrides: overrides);
```

## Command map (PowerShell)

| Cmdlet | Purpose |
| --- | --- |
| `Invoke-DDCertificateInventory` | Live discovery and snapshot capture |
| `Get-DDCertificateInventorySnapshot` | Read raw persisted snapshots |
| `Get-DDCertificateInventoryCtDiagnostics` | Query native CT ingestion diagnostics (state/lag/circuit/failure) |
| `Get-DDCertificateInventoryCtHealth` | Build CT health timeline and threshold status across snapshots |
| `Get-DDCertificateInventorySummary` | Portfolio summary |
| `Get-DDCertificateInventoryQuery` | Structured filtering/search |
| `Get-DDCertificateInventoryRisk` | Risk scoring and prioritization |
| `Get-DDCertificateInventoryDrift` | Endpoint drift over time |
| `Get-DDCertificateInventoryDiff` | Snapshot-to-snapshot deltas |
| `Get-DDCertificateInventoryReuse` | Certificate reuse/fan-out map |
| `Get-DDCertificateInventoryPolicy` | Baseline policy evaluation |
| `Get-DDCertificateInventoryPolicyDrift` | Compliance drift between snapshots |

Native CT diagnostics example:

```powershell
Get-DDCertificateInventoryCtDiagnostics `
    -CacheDirectory .\cert-monitor `
    -SinceUtc (Get-Date).ToUniversalTime().AddDays(-7) `
    -State Failed,CircuitOpen `
    -LagAfterMin 10000 `
    -MaxResults 500
```

Native CT diagnostics threshold alerting:

```powershell
# Warn on threshold breach (non-terminating by default)
Get-DDCertificateInventoryCtDiagnostics `
    -CacheDirectory .\cert-monitor `
    -LatestOnly `
    -MaxFailed 0 `
    -MaxCircuitOpen 0 `
    -MaxLagAfter 5000

# Fail the pipeline when breached
Get-DDCertificateInventoryCtDiagnostics `
    -CacheDirectory .\cert-monitor `
    -LatestOnly `
    -MaxFailed 0 `
    -MaxCircuitOpen 0 `
    -MaxLagAfter 5000 `
    -FailOnThresholdBreach
```

CLI threshold alerting (returns exit code `2` when breached):

```bash
DomainDetective.CLI CertificateInventoryCtDiagnostics \
  --cache-dir ./cert-monitor \
  --latest-only \
  --max-failed 0 \
  --max-circuit-open 0 \
  --max-lag-after 5000
```

Use `--no-fail-on-threshold-breach` if you only want warning output in CLI runs.

CT health timeline (status panel + last breach style data):

```powershell
Get-DDCertificateInventoryCtHealth `
    -CacheDirectory .\cert-monitor `
    -SinceUtc (Get-Date).ToUniversalTime().AddDays(-14) `
    -MaxSnapshots 60 `
    -MaxFailed 0 `
    -MaxCircuitOpen 0 `
    -MaxLagAfter 5000
```

```bash
DomainDetective.CLI CertificateInventoryCtHealth \
  --cache-dir ./cert-monitor \
  --since-utc 2026-01-01 \
  --max-snapshots 60 \
  --max-failed 0 \
  --max-circuit-open 0 \
  --max-lag-after 5000
```

`CertificateInventoryCtHealth` returns:

- per-snapshot status (`Healthy`, `Warning`, `Breached`, `NoDiagnostics`)
- failed/circuit-open/max-lag metrics
- latest status and last breach timestamp

CLI exit code behavior:

- `2` when thresholds are breached (latest snapshot by default)
- `--fail-on-any-breach` to fail when any returned snapshot is breached
- `--no-fail-on-threshold-breach` for warning-only mode

## Recommended operating model for 8k+ domains

- Keep one authoritative domain list and deduplicate before capture.
- Use a stable `CacheDirectory` on persistent storage.
- Run scheduled captures (for example every 6-24 hours).
- Use `-LatestOnly` queries for current posture dashboards.
- Use drift/diff/policy-drift for alerting workflows.
- Keep historical snapshots long enough for trend windows (30/90/180 days based on requirements).
- Tune `-MaxParallelism` and `-DiscoveryParallelism` according to network limits and resolver behavior.
- Use CT enrichment to detect cert evidence beyond currently reachable endpoints, then validate by endpoint probing.

## Related docs

- [CT_TIMELINE.MD](CT_TIMELINE.MD)
- [SUBDOMAINS.MD](SUBDOMAINS.MD)

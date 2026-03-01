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

## Discovery coverage and sources

DomainDetective combines endpoint probing and CT evidence:

| Source | What you get | Configuration |
| --- | --- | --- |
| HTTPS probing | Live leaf cert, chain, issuer/root, EKU/auth profile, validity, hostname match, protocol/service | Included by default (apex + `www`) |
| MX discovery + STARTTLS | Mail host certs from SMTP 25/587; optional IMAPS/POP3S | Default includes STARTTLS; IMAP/POP3 optional |
| Additional endpoints | Explicit app/service targets (`https://`, `smtp://`, etc.) | `-Endpoint` / `AdditionalEndpoints` |
| Public CT API (`crt.sh`) | CT presence and source evidence for observed certs | Enabled by default template |
| Optional CT APIs (Shodan/Censys/custom) | Wider CT discovery source coverage | `CtProfile`, source toggles, API keys/templates |

Notes:

- `crt.sh` is used by default via `https://crt.sh/?sha256={0}&output=json`.
- `crt.sh` is public and does not require API credentials in this flow.
- For commercial sources, credentials are required (for example Shodan/Censys).
- MX hosts are often inbound-only and may not expose `587/993/995`; empty certificate fields on those rows usually indicate service not reachable on that endpoint, not parser failure.

## PowerShell end-to-end examples

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
    -CtProfile Extended `
    -IncludeCtSubdomains `
    -VerifyCtSubdomains `
    -EnableShodanCtSource `
    -ShodanApiKeyEnv SHODAN_API_KEY `
    -IncludeImapTls `
    -IncludePop3Tls `
    -MaxParallelism 24 `
    -DiscoveryParallelism 32 `
    -Verbose

$capture | Format-List CapturedAtUtc,SnapshotPath,DomainCount,MxHostCount,EntryCount,ValidCount,ExpiredCount,FailedCount
```

For large domains where you want CT-seen hostnames added to scan scope:

```powershell
Invoke-DDCertificateInventory `
    -DomainName eurofins.com `
    -CacheDirectory .\cert-monitor `
    -IncludeCtSubdomains `
    -MaxCtSubdomainsPerDomain 5000 `
    -MaxCtRowsPerDomain 20000
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
    CtProfile = CertificateCtEnrichmentProfile.Extended,
    EnableShodanCtSource = true,
    ShodanApiKey = Environment.GetEnvironmentVariable("SHODAN_API_KEY"),
    IncludeImapTls = true,
    IncludePop3Tls = true,
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
| `Get-DDCertificateInventorySummary` | Portfolio summary |
| `Get-DDCertificateInventoryQuery` | Structured filtering/search |
| `Get-DDCertificateInventoryRisk` | Risk scoring and prioritization |
| `Get-DDCertificateInventoryDrift` | Endpoint drift over time |
| `Get-DDCertificateInventoryDiff` | Snapshot-to-snapshot deltas |
| `Get-DDCertificateInventoryReuse` | Certificate reuse/fan-out map |
| `Get-DDCertificateInventoryPolicy` | Baseline policy evaluation |
| `Get-DDCertificateInventoryPolicyDrift` | Compliance drift between snapshots |

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

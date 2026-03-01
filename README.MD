[![.NET Tests](https://github.com/EvotecIT/DomainDetective/actions/workflows/dotnet-tests.yml/badge.svg)](https://github.com/EvotecIT/DomainDetective/actions/workflows/dotnet-tests.yml)
[![PowerShell Tests](https://github.com/EvotecIT/DomainDetective/actions/workflows/powershell-tests.yml/badge.svg)](https://github.com/EvotecIT/DomainDetective/actions/workflows/powershell-tests.yml)
[![codecov](https://codecov.io/gh/EvotecIT/DomainDetective/branch/master/graph/badge.svg)](https://codecov.io/gh/EvotecIT/DomainDetective)
[![Discord](https://img.shields.io/discord/508328927853281280?style=flat-square&label=discord%20chat)](https://evo.yt/discord)

Domain Detective is a domain, DNS, and email security auditing toolkit.

What we deliver today:

- C# library: compose and automate checks in .NET
- PowerShell module: fast, scriptable cmdlets with sensible aliases
- Cross‑platform CLI: quick interactive and batch workflows (Windows/macOS/Linux)

Why: enable offline, automatable versions of the tools you usually find on the web — repeatable, script‑friendly and ready for CI/CD or air‑gapped environments.

## Features Overview

DNS & Infrastructure

- NS, SOA, Delegation, zone transfer checks
- MX, PTR/Reverse, FCrDNS
- DNSSEC: chain and DS validation
- TTL analysis; wildcard detection; EDNS support; open resolver
- DNS propagation (ad‑hoc + background monitor)

Email Authentication & Transport

- SPF: chain traversal and flattening; DNS‑lookup budget; terminal policy (-all); trailing content; null/exists lookups; macro validation (RFC 7208).
- DKIM: key presence and length, weak/old keys; canonicalization/hash checks; deprecated tags; per‑selector analysis (RFC 6376/8617 for ARC where applicable).
- DMARC: policy and alignment, pct/sp modes, rua/ruf parsing, aggregate/forensic import (RFC 7489 / dmarcbis draft).
- BIMI: record presence and logo/VMC hints (draft spec).
- MTA‑STS and TLS‑RPT: policy retrieval/validation and reporting posture (RFC 8461 / RFC 8460).
- Transport posture: SMTP STARTTLS, SMTP banner RFC‑conformance, IMAP/POP3 TLS, open relay checks, mail latency.

Web & Certificates

- HTTPS reachability (HTTP/2/3), enforced HTTPS redirects, forms over HTTPS, mixed‑content flags.
- Security headers posture: HSTS, CSP, Referrer‑Policy, Permissions‑Policy, X‑Frame‑Options and more.
- Certificate insights: chain/issuer/CT presence, key algorithm/size, weak/SHA‑1 flags, OCSP stapling; optional DANE/TLSA; S/MIMEA.

Static Website Scan

- Crawl starting URL, follow in‑scope links, and map redirect chains.
- Detect broken links/resources (first‑party vs third‑party) and mixed content.
- Surface missing/weak headers (CSP, HSTS, Referrer‑Policy, etc.).
- Third‑party inventory; top‑by‑bytes/requests; simple tracker/analytics detection.
- Lightweight technology fingerprinting from headers/body (no headless browser required).
- Robots.txt and sitemap hints to guide or explain coverage.

Reputation, Registry & Routing

- Threat intel hooks and feed ingestion (configurable), VirusTotal helpers.
- DNSBL lookups with customizable provider lists (domain/IP modes).
- WHOIS and RDAP (RFC 9083) for registration data.
- RPKI origin validation (route/origin hygiene).

Discovery, Exposure & Identity

- Autodiscover (mail client setup), Security.txt, Contact TXT.
- Directory exposure checks (well‑known paths/leaks).
- Identity provider info (OIDC discovery / user realm hints).

Infrastructure Hygiene

- Dangling/Takeover‑prone CNAMEs, flattening service detection.
- Subdomain enumeration, IP neighbor analysis.
- Reverse DNS/FCrDNS consistency, wildcard DNS detection.

Network Services

- Port availability and lightweight port scan profiles.
- SNMP and NTP posture checks.

Reporting & UX

- HTML, Word, Excel, PDF (basic), Markdown/MarkdownHtml, and JSON reports
- Interactive CLI wizard, PowerShell views, and pipeline-friendly composition
- Ordering controls for per-domain sections across Word/HTML/Markdown/Excel

### Report ordering (Word/HTML/Markdown/Excel)

- `DomainOrder`: Alphabetical (default) or Input (first-seen order)
- `SectionOrderMode`: Canonical (default), Input, or Custom
- `SectionOrder`: explicit list of section keys when using Custom

Canonical section order:
MX, SPF, DKIM, DMARC, DMARC Aggregate, ARC, BIMI, DNSBL, RPKI, Registration, NS, SOA, TTL, ZoneTransfer, Wildcard, CAA, Classification, MTA-STS, TLS-RPT, TLS-RPT Reports, MAILTLS, DNSSEC, DANE.

Executive Summary columns remain canonical across formats; ordering affects per-domain sections only.

### Project Goals

- Offline‑first: make common online tools available locally, safely and repeatably.
- Automation‑ready: clean models, stable outputs, designed for scripting and CI/CD.
- Cross‑platform: consistent experience on Windows, macOS and Linux.
- Extensible: C# SDK + PowerShell + CLI, with provider hooks.

### Output & Views

- Raw: strongly‑typed analysis models suitable for automation and downstream processing (`view.Raw`).
- Narrative: persona‑driven, human‑friendly storyline in CLI/PowerShell (without polluting the raw data).
- Highlights: concise status, counts and key flags for dashboards and at‑a‑glance summaries.

These layers are available both from the CLI and PowerShell; use summaries for quick triage and drill into raw for evidence and provenance.

### Standards Coverage (examples)

- SPF: RFC 7208 • DKIM: RFC 6376 • ARC: RFC 8617
- DMARC: RFC 7489 (plus dmarcbis draft) • BIMI (draft)
- MTA‑STS: RFC 8461 • TLS‑RPT: RFC 8460
- DANE/TLSA: RFC 6698 • SMIMEA: RFC 8162
- HSTS: RFC 6797 • EDNS(0): RFC 6891 • RDAP: RFC 9083

### Roadmap

See TODO.md for the current backlog and roadmap.

## Available Cmdlets and Aliases

### Email

| Prefixed Name                  | Alias Name                 | Purpose                       |
| ------------------------------ | -------------------------- | ----------------------------- |
| `Test-DDEmailArcRecord`        | `Test-EmailArc`            | Validate ARC headers          |
| `Test-DDEmailAutoDiscover`     | `Test-EmailAutoDiscover`   | Check mail client discovery   |
| `Test-DDEmailAddress`          | `Test-EmailAddress`        | Validate mailbox reachability |
| `Test-DDEmailBimiRecord`       | `Test-EmailBimi`           | Verify BIMI record            |
| `Test-DDEmailDkimRecord`       | `Test-EmailDkim`           | Verify DKIM selectors         |
| `Test-DDEmailDmarcRecord`      | `Test-EmailDmarc`          | Verify DMARC policy           |
| `Test-DDEmailSpfRecord`        | `Test-EmailSpf`            | Verify SPF policy             |
| `Test-DDEmailTlsRptRecord`     | `Test-EmailTlsRpt`         | Inspect TLS-RPT               |
| `Test-DDEmailMtaSts`           | `Test-EmailMtaSts`         | Verify MTA-STS policy         |
| `Test-DDEmailStartTls`         | `Test-EmailStartTls`       | Check STARTTLS advertisement  |
| `Test-DDEmailSmtpTls`          | `Test-EmailSmtpTls`        | Check SMTP TLS posture        |
| `Test-DDEmailProtocolTls`      | `Test-EmailProtocolTls`    | SMTP/IMAP/POP3 TLS checks     |
| `Test-DDEmailOpenRelay`        | `Test-EmailOpenRelay`      | Detect open SMTP relay        |
| `Get-DDEmailMessageHeaderInfo` | `Get-EmailHeaderInfo`      | Parse raw email headers       |
| `Test-DDEmailLatency`          | `Test-EmailLatency`        | Measure SMTP responsiveness   |
| `Test-DDEmailImapTls`          | `Test-EmailImapTls`        | IMAP TLS check                |
| `Test-DDEmailPop3Tls`          | `Test-EmailPop3Tls`        | POP3 TLS check                |
| `Test-DDEmailSmtpBanner`       | `Test-EmailSmtpBanner`     | Inspect SMTP banner           |
| `Test-DDDmarcAggregate`        | `Test-EmailDmarcAggregate` | Parse DMARC aggregate reports |
| `New-DDDmarcRecord`            | `New-DmarcRecord`          | Build DMARC record            |

### Email Address Validation

PowerShell example:
```powershell
Test-DDEmailAddress -EmailAddress "user@example.com" -SmtpProbe -CheckCatchAll
```

CLI example:
```bash
DomainDetective.CLI ValidateEmail user@example.com --smtp --catch-all --smtp-max-hosts 2
```

SMTP rules example:
```powershell
Test-DDEmailAddress -EmailAddress "user@example.com" -SmtpProbe -SmtpRulesPath "./smtp-rules.json"
```

```bash
DomainDetective.CLI ValidateEmail user@example.com --smtp --smtp-rules ./smtp-rules.json --no-builtin-smtp-rules
```

Optional controls:
- Use `-EnableProviderWebChecks` (or `--provider-web`) to enable provider web checks when available.
- Use `-ProtonAuthCookie`/`-ProtonUid` (or `--proton-auth`/`--proton-uid`) to enable Proton checks (requires a valid AUTH cookie and `x-pm-uid`).
- Use `-SmtpRulesPath` (or `--smtp-rules`) to supply custom SMTP rules JSON and `-DisableBuiltinSmtpRules` to ignore built-in rules.
- Use `-AllowB2CCatchAll` (or `--allow-b2c-catch-all`) to allow catch-all probing for consumer providers.
- Use `-AllowInvalidSmtpCertificates` (or `--smtp-allow-invalid-cert`) to skip SMTP TLS certificate validation (not recommended).
- Use `-SmtpTimeoutSeconds`/`-SmtpRetryDelaySeconds` (or `--smtp-timeout`/`--smtp-retry-delay`) to tune SMTP timing.
- Use `-B2CProvidersPath` (or `--b2c-providers`) to override the B2C provider list.
- Use `-DisableFreeProvidersAsB2C` (or `--no-free-as-b2c`) to avoid treating free providers as B2C when no explicit match exists.
- Use `-SmtpProbeDelaySeconds` (or `--smtp-delay`) to add a delay between SMTP probe attempts for rate limiting.
- Built-in SMTP rules are enabled by default. See `Docs/EmailSmtpRules.md` for schema, examples, and Proton auth notes.
- Provider web checks are currently implemented for Yahoo, Microsoft consumer domains, and Proton (with auth).
- Provider web checks rely on undocumented endpoints and may change or rate-limit without notice.
- Avoid passing Proton auth values via command line where they may appear in shell history or process listings.
- SMTP probing can trigger abuse protections on some providers; apply delays for bulk runs and consider proxies when needed.

### Web

| Prefixed Name              | Alias Name               | Purpose                                        |
| -------------------------- | ------------------------ | ---------------------------------------------- |
| `Test-DDWebsite`           | `Test-Website`           | Combined website check (cert + HTTPS security) |
| `Test-DDWebsiteSecurity`   | `Test-WebsiteSecurity`   | HTTPS security headers + mixed content         |
| `Test-DDDomainCertificate` | `Test-DomainCertificate` | Website certificate incl. TLS grade            |

### DNS

| Prefixed Name                   | Alias Name                    | Purpose                                |
| ------------------------------- | ----------------------------- | -------------------------------------- |
| `Test-DDDnsCaaRecord`           | `Test-DnsCaa`                 | Verify CAA                             |
| `Test-DDDnsNsRecord`            | `Test-DnsNs`                  | Verify NS                              |
| `Test-DDDnsSoaRecord`           | `Test-DnsSoa`                 | Verify SOA                             |
| `Test-DDDnsSecStatus`           | `Test-DnsSec`                 | Verify DNSSEC                          |
| `Test-DDDnsBlacklist`           | `Test-DnsBlacklist`           | Check DNSBL (domain + MX IPs)          |
| `Test-DDMailDomainClassification` |  | Classify sending/receiving/parked + signals |
| `Test-DDDnsOpenResolver`        | `Test-DnsOpenResolver`        | Detect open resolver                   |
| `Test-DDDnsDanglingCname`       | `Test-DnsDanglingCname`       | Find dangling CNAME                    |
| `Test-DDDnsPropagation`         | `Test-DnsPropagation`         | Check global propagation               |
| `Start-DDDnsPropagationMonitor` | `Start-DnsPropagationMonitor` | Background propagation monitor         |
| `Stop-DDDnsPropagationMonitor`  | `Stop-DnsPropagationMonitor`  | Stop propagation monitor               |
| `Test-DDDnsTtl`                 | `Test-DnsTtl`                 | TTL analysis                           |
| `Test-DDDnsTunneling`           | `Test-DnsTunneling`           | Detect DNS tunneling (logs)            |
| `Test-DDDnsWildcard`            | `Test-DnsWildcard`            | Detect wildcard catch-all              |
| `Test-DDDnsEdnsSupport`         | `Test-DnsEdnsSupport`         | EDNS support                           |
| `Test-DDDnsHealth`              | `Test-DnsHealth`              | Authoritative SOA/apex/TTL consistency |
| `Test-DDDnsSmimeaRecord`        | `Test-DnsSmimea`              | S/MIMEA                                |
| `Test-DDDnsForwardReverse`      | `Test-DnsFcrDns`              | FCrDNS                                 |
| `Test-DDDnsMxRecord`            | `Test-DnsMx`                  | MX records                             |
| `Test-DDDnsDelegation`          | `Test-DnsDelegation`          | Parent NS/glue consistency             |
| `Test-DDDnsReverseDns`          | `Test-DnsReverseDns`          | Reverse DNS                            |
| `Test-DDDnsZoneTransfer`        | `Test-DnsZoneTransfer`        | AXFR exposure                          |

### Domain

| Prefixed Name                | Alias Name                 | Purpose                                                                |
| ---------------------------- | -------------------------- | ---------------------------------------------------------------------- |
| `Test-DDDomainContactRecord` | `Test-DomainContact`       | WHOIS contact sanity                                                   |
| `Test-DDDomainSecurityTxt`   | `Test-DomainSecurityTxt`   | security.txt checks                                                    |
| `Test-DDDomainCertificate`   | `Test-DomainCertificate`   | Website certificate checks                                             |
| `Test-DDDomainOverallHealth` | `Test-DomainHealth`        | Composite health; returns a View (with Raw), supports -Export* |
| `Test-DDDesiredState`        | `Test-DesiredState`        | Validate domains against an organization-specific desired state baseline |
| `Get-DDDomainWhois`          | `Get-DomainWhois`          | WHOIS                                                                  |
| `Get-DDDomainFlattenedSpfIp` | `Get-DomainFlattenedSpfIp` | Flatten SPF to IPs                                                     |
| `Test-DDDomainThreatIntel`   | `Test-DomainThreatIntel`   | Threat intel lookups                                                   |
| `Get-DDRdap`                 | `Get-Rdap`                 | RDAP                                                                   |
| `Get-DDRdapObject`           | `Get-RdapObject`           | RDAP raw object                                                        |
| `Get-DDSearchEngineInfo`     | `Get-SearchEngineInfo`     | Search engine queries                                                  |

### TLS & Networking

| Prefixed Name                    | Alias Name                     | Purpose                                    |
| -------------------------------- | ------------------------------ | ------------------------------------------ |
| `Test-DDTlsDaneRecord`           | `Test-TlsDane`                 | DANE/TLSA                                  |
| `Get-DDTlsCertificateInfo`       | `Get-CertificateInfo`          | Parse PEM/DER certs                        |
| `Test-DDNetworkIpNeighbor`       | `Test-NetworkIpNeighbor`       | IP neighbors (add -IncludeMX for mail IPs) |
| `Test-DDNetworkPortAvailability` | `Test-NetworkPortAvailability` | Port scanning                              |

### Configuration & Data

| Prefixed Name               | Alias Name             | Purpose             |
| --------------------------- | ---------------------- | ------------------- |
| `Add-DDDnsblProvider`       | `Add-DnsblProvider`    | Manage DNSBL        |
| `Remove-DDDnsblProvider`    | `Remove-DnsblProvider` | Manage DNSBL        |
| `Clear-DDDnsblProviderList` | `Clear-DnsblProvider`  | Manage DNSBL        |
| `Import-DDDnsblConfig`      | `Import-DnsblConfig`   | Manage DNSBL        |
| `Import-DDDmarcReport`      | `Import-DmarcReport`   | DMARC aggregate zip |
| `Import-DDDmarcForensic`    | `Import-DmarcForensic` | DMARC forensic zip  |
| `Import-DDEmailTlsRpt`      | `Import-EmailTlsRpt`   | TLS-RPT JSON        |

### Time Series

| Prefixed Name                     | Alias Name                      | Purpose                                             |
| --------------------------------- | ------------------------------- | --------------------------------------------------- |
| `Import-DDDmarcAggregateSnapshot` | `Import-DmarcAggregateSnapshot` | DMARC aggregate snapshots (path/IMAP) → store       |
| `Get-DDDmarcAggregateTimeSeries`  | `Get-DmarcAggregateTimeSeries`  | DMARC aggregate time-series view (report section)   |
| `Import-DDTlsRptReportSnapshot`   | `Import-TlsRptReportSnapshot`   | TLS-RPT reports (path/IMAP) → store                 |
| `Get-DDTlsRptReportsTimeSeries`   | `Get-TlsRptReportsTimeSeries`   | TLS-RPT reports time-series view (report section)   |
| `Import-DDRegistrationSnapshot`   | `Import-RegistrationSnapshot`   | WHOIS/RDAP registration snapshot → store            |
| `Get-DDRegistrationDrift`         | `Get-RegistrationDrift`         | Registration structured drift view (report section) |
| `Invoke-DDCertificateInventory` | - | Capture certificate inventory snapshot from domains/endpoints |
| `Get-DDCertificateInventorySnapshot` | - | Read raw persisted certificate inventory snapshots |

## Reports / Exporting

- Compose any mix via pipeline:

```
Import-Module ./Module/DomainDetective.psd1 -Force

$spf   = Test-DDEmailSpfRecord -DomainName 'evotec.pl'
$dnsbl = Test-DDDnsBlacklist   -NameOrIpAddress 'evotec.pl'
($spf + $dnsbl) | Export-DDSecurityReport -Scope Detailed -ExportFormat Word -ExportPath .\\Reports -OpenReport
```

- Time-series sections (DMARC Aggregate / TLS-RPT Reports / Registration drift):

```
Import-Module ./Module/DomainDetective.psd1 -Force

# Ingest reports/snapshots (run on a schedule)
Import-DDDmarcAggregateSnapshot -StorePath .\\Store -Path .\\Reports\\DMARC
Import-DDTlsRptReportSnapshot   -DomainName example.com -StorePath .\\Store -Path .\\Reports\\TLSRPT
Import-DDRegistrationSnapshot   -DomainName example.com -StorePath .\\Store
Invoke-DDCertificateInventory -DomainName example.com,example.org -CacheDirectory .\\cert-monitor
# Optional CT enrichment profile for inventory capture (public + optional commercial sources):
Invoke-DDCertificateInventory -DomainName example.com -CacheDirectory .\\cert-monitor -CtProfile Extended -EnableShodanCtSource -ShodanApiKeyEnv SHODAN_API_KEY
# Read latest raw snapshot (full entries) or metadata only:
Get-DDCertificateInventorySnapshot -CacheDirectory .\\cert-monitor -Latest
Get-DDCertificateInventorySnapshot -CacheDirectory .\\cert-monitor -SinceUtc (Get-Date).ToUniversalTime().AddDays(-7) -WithoutEntries

# Build report sections from the store
$dmarcAgg = Get-DDDmarcAggregateTimeSeries -DomainName example.com -StorePath .\\Store
$tlsRpt   = Get-DDTlsRptReportsTimeSeries  -DomainName example.com -StorePath .\\Store
$reg      = Get-DDRegistrationDrift        -DomainName example.com -StorePath .\\Store

($dmarcAgg + $tlsRpt + $reg) | Export-DDSecurityReport -Scope Detailed -ExportFormat Word -ExportPath .\\Reports -OpenReport
```

- Or inline with a script block:

```
Import-Module ./Module/DomainDetective.psd1 -Force

Export-DDSecurityReport -Scope Detailed -ExportFormat Word -ExportPath .\\Reports -OpenReport -Compose {
  Test-DDEmailSpfRecord              -DomainName 'evotec.pl'
  Test-DDDnsBlacklist                -NameOrIpAddress 'evotec.xyz'
  Test-DDMailDomainClassification    -DomainName 'evotec.pl'
}
```

- Or inline using positional ScriptBlock (no `-Compose`):

```
Import-Module ./Module/DomainDetective.psd1 -Force

Export-DDSecurityReport -Scope Detailed -ExportFormat Markdown -ExportPath .\\Reports {
  Test-DDEmailSpfRecord  -DomainName 'evotec.pl','evotec.xyz'
  Test-DDEmailDkimRecord -DomainName 'evotec.pl','evotec.xyz'
  Test-DDEmailDmarcRecord -DomainName 'evotec.pl','evotec.xyz'
  Test-DDDnsNsRecord     -DomainName 'evotec.pl'
  Test-DDDnsSecStatus    -DomainName 'evotec.pl'
}
```

- Metadata overrides (PowerShell):
  - Set defaults once:
    - `Set-DDExportOptions -Title "Evotec — Q3 Portfolio Review" -Subject "Executive summary and remediation plan" -Category "Email Security" -Keywords "SPF,DKIM,DMARC" -Creator "Evotec"`
  - Or per-call:
    - `Export-DDSecurityReport -ExportFormat Word -Title "Evotec — MX Review" -Subject "MX and transport policies"`

- Notes:
  - The Word header shows the generated timestamp; company branding can be applied via export options.
  - Executive Summary → Overview includes the domain count and total warnings/errors across all domains.

## DNSBL Configuration
DNSBL lists used for blacklist checks can be customized. `DNSBLAnalysis` comes with a built-in list, but you can modify it at runtime. Each list entry exposes `Domain`, `Enabled`, and `Comment` fields. Use the following methods on `DNSBLAnalysis` to manage the list:

- `AddDNSBL`/`AddDNSBL(IEnumerable<string>)`
- `RemoveDNSBL`
- `ClearDNSBL`
- `LoadDNSBL`

You can load a custom list from a file using `LoadDNSBL`. Additionally, JSON files describing DNSBL providers can be imported with `ImportDnsblConfig`.

Flags and knobs:
- `-TreatAsDomain`: Force domain-mode (domain lists + MX IPs) even if input looks like an IP.
- `-TreatAsIp`: Force IP-mode (only IP DNSBLs). Fails if input is not a valid IP.
- `-MaxConcurrency`: Hint to the resolver to cap concurrency (applied if supported by the underlying DNS client).
- `-BlacklistedOnly`: Filter output to only entries that are actually listed.

Example usage in C#:

```csharp
var analysis = new DNSBLAnalysis();

// add a provider
analysis.AddDNSBL("dnsbl.example.com", comment: "custom");

// remove a provider
analysis.RemoveDNSBL("dnsbl.example.com");

// clear all configured providers
analysis.ClearDNSBL();

// load providers from JSON configuration
analysis.LoadDnsblConfig("DnsblProviders.json", overwriteExisting: true);
```

Same actions are available from PowerShell using dedicated cmdlets:

```powershell
Add-DnsblProvider -Domain 'dnsbl.example.com' -Comment 'custom'
Remove-DnsblProvider -Domain 'dnsbl.example.com'
Clear-DnsblProvider
Import-DnsblConfig -Path './DnsblProviders.json' -OverwriteExisting
```

## Website Certificates (overview)
`VerifyWebsiteCertificate` can be called with or without a URL scheme. When the scheme is omitted, `https://` is used automatically before checking the certificate.

The `CertificateAnalysis` result now includes:

- `KeyAlgorithm` and `KeySize` for the leaf certificate.
- `WeakKey` when the key is under 2048 bits.
- `Sha1Signature` when the certificate uses SHA‑1.
- `IsSelfSigned` when the certificate subject equals the issuer and the chain length is one.
- With `CaptureTlsDetails` enabled, `TlsProtocol`, `CipherAlgorithm` and `CipherStrength` describe the negotiated cipher-suite.
- `PresentInCtLogs` when the certificate appears in public CT logs.
- `CtTemplateFormatErrors` for CT source template/configuration issues encountered during discovery.
- `CtLogApiTemplates` allows customizing the list of CT log APIs queried.
- `SkipRevocation` disables CRL and OCSP checks. Use with care as revoked certificates may appear valid.

### Combined Website Check
PowerShell users can run a combined check returning a single `WebsiteInfo` object:

```powershell
Test-Website -DomainName evotec.xyz | Select-Object Area,Check,Status,Summary,CertificateGrade,HttpGrade
```
This aggregates `CertificateInfo` and `HttpInfo` with grades, HSTS presence, and mixed-content flag.


## DKIM Analysis (overview)
`DkimRecordAnalysis` exposes several indicators:

- `WeakKey` when the RSA key is under 2048 bits.
- `OldKey` when the creation date is over 12 months old.
- `DeprecatedTags` listing tags such as `g` or `h=sha1`.

## SMTP TLS (overview)
`SMTPTLSAnalysis` now stores the negotiated certificate and reports expiration
details and chain validity for each server.

## HTTP Security Headers (overview)
`HttpAnalysis.DefaultSecurityHeaders` lists security headers that are inspected when header collection is enabled. The list includes `Content-Security-Policy`, `Referrer-Policy`, `X-Frame-Options`, `Permissions-Policy`, `Origin-Agent-Cluster` and several Cross-Origin policies. You can modify the list to capture additional headers.
`HttpAnalysis` also sets `HstsPreloaded` when the host is found in the bundled HSTS preload list.

Each HTTP check also computes a coarse `Grade` (A–F) summarizing header posture and mixed-content. See `Test-WebsiteSecurity` and `Test-Website`.


## Build and Test

Use the [.NET SDK](https://dotnet.microsoft.com/) to restore dependencies, build the solution and execute tests:

```bash
dotnet restore
dotnet build DomainDetective.sln
dotnet test DomainDetective.Tests/DomainDetective.Tests.csproj
```

PowerShell specific tests can be run with:

```powershell
pwsh ./Module/DomainDetective.Tests.ps1
```

RPKI validation in C#:

```csharp
var hc = new DomainHealthCheck();
await hc.VerifyRPKI("example.com");
foreach (var r in hc.RpkiAnalysis.Results)
    Console.WriteLine($"{r.IpAddress} {r.Asn} {r.Valid}");
```

<!-- CLI usage moved under Install & Usage -->

## Install & Usage

Import the module and call any of the testing cmdlets:

```powershell
Import-Module ./Module/DomainDetective.psd1 -Force
Test-EmailSpf -DomainName "example.com"
Test-EmailAutoDiscover -DomainName "example.com"
Test-DnsFcrDns -DomainName "example.com"
```

By default, all DNS-related cmdlets use the system DNS resolver. You can specify
a different endpoint with the **-DnsEndpoint** parameter when needed.

Analyze TTL values:

```powershell
Test-DnsTtl -DomainName "example.com"
```

TTL metadata is also captured during email controls checks (SPF/DMARC/DKIM/MX/MTA-STS/TLS-RPT) and surfaced in the returned Views (and exports) without requiring `-HealthCheckType TTL`.

Get concise summaries (Area/Check/Status/Summary) for views returned by cmdlets:

```powershell
Get-DDApexAddressInfo -DomainName "example.com" | Select-Object Area,Check,Status,Summary
```

Check wildcard DNS:

```powershell
Test-DnsWildcard -DomainName "example.com"
```

Check EDNS support:

```powershell
Test-DnsEdnsSupport -DomainName "example.com"
```
Query an S/MIMEA record:
```powershell
Test-DnsSmimea -EmailAddress "user@example.com"
```

Analyze ARC headers from PowerShell:

```powershell
Get-Content './headers.txt' -Raw | Test-EmailArc
```

Validate RPKI origins:

```powershell
Test-Rpki -DomainName "example.com"
```

### CLI examples

Run the example project and CLI scenarios:

```bash
dotnet run --project DomainDetective.Example example.com --json
ddcli check example.com --checks autodiscover
ddcli check example.com --subdomain-policy
ddcli check example.com --checks fcrdns
ddcli TestSMIMEA user@example.com
ddcli DnsPropagation --domain example.com --record-type A

 ddcli check example.com --check-web
 ddcli check example.com --checks DNSHEALTH

#### SPF host simulation

```
ddcli SpfTestHost example.com --ip 192.0.2.10 --sender postmaster@example.com --json
```

IdP tenant hints in C#:

```csharp
var hc = new DomainHealthCheck();
await hc.VerifyIdpInfo("example.com");
var idp = hc.IdpInfoAnalysis;
Console.WriteLine($"Tenant: {idp.TenantId}, Namespace: {idp.NameSpaceType}, FederatedAuthUrl: {idp.FederatedAuthUrl}");
```

DMARC aggregate enrichment and summaries in C#:

```csharp
var paths = Directory.GetFiles("./reports", "*.xml");
var reports = paths.Select(p => DmarcReportParser.Parse(p)).ToList();
// Enrich records with ASN and country
await DmarcAggregateEnrichment.EnrichAsync(reports.SelectMany(r => r.Records));

// Reporter summary
var pairs = reports.SelectMany(r => r.Records.Select(rec => (Report: r, Record: rec)));
var byReporter = pairs.SummarizeFailuresByReporter().OrderByDescending(x => x.Count);

// By ASN
var all = reports.SelectMany(r => r.Records);
var byAsn = all.SummarizeFailuresByAsn().OrderByDescending(x => x.Count);

// By Country
var byCountry = all.SummarizeFailuresByCountry().OrderByDescending(x => x.Count);
```
Returns a verdict (pass/fail/softfail/neutral/permerror), the matched token/type and the include/redirect chain that led to the match.
```

### CLI wizard

```bash
ddcli
```
Guides you through domain entry, check selection, and JSON vs summary output.
For web-focused checks from CLI:

```bash
 ddcli example.com --check-web
 ddcli example.com --checks DNSHEALTH
```

### CLI: analyze messages

```bash
ddcli AnalyzeMessageHeader --file ./headers.txt --json
ddcli AnalyzeARC --file ./headers.txt --json
```

### CLI artifacts

```bash
# List recent runs from artifacts index
ddcli RunsList --subject example.com --count 5

# Open the most recent run (scan.json or directory)
ddcli RunsOpen --subject example.com
```

### CLI: time-series store (DMARC Aggregate / TLS-RPT / Registration)

```bash
# Ingest reports/snapshots (run on a schedule)
ddcli ImportDmarcAggregateSnapshot ./Reports/DMARC --store-path ./Store
ddcli ImportTlsRptReportSnapshot   example.com ./Reports/TLSRPT --store-path ./Store
ddcli ImportRegistrationSnapshot   example.com --store-path ./Store

# Optional: IMAP ingestion (use --imap-subject-contains to narrow scan; attachment size limit; 0 = unlimited)
ddcli ImportDmarcAggregateSnapshot --store-path ./Store --imap-host imap.example.com --imap-user user@example.com --imap-password-env DMARC_IMAP_PASSWORD --mailbox INBOX --since-utc 2025-01-01 --max-attachment-mb 50
ddcli ImportTlsRptReportSnapshot   example.com --store-path ./Store --imap-host imap.example.com --imap-user user@example.com --imap-password-env TLSRPT_IMAP_PASSWORD --mailbox INBOX --since-utc 2025-01-01 --max-attachment-mb 50

# Generate report with time-series sections
ddcli GenerateReport example.com --format word --store-path ./Store
ddcli GenerateReport example.com --format html --store-path ./Store
```

<!-- Tables moved to top under "Available Cmdlets and Aliases" -->

## Configuration knobs (common)

- Dns endpoint: most cmdlets accept `-DnsEndpoint` to control resolution.
- Scope selection: DNS propagation supports `-Country`, `-Location`, `-Take` and background monitor with start/stop cmdlets.
- Snapshots and diffs: `-SnapshotPath` and `-Diff` (WHOIS) compare against stored snapshots.
- Time-series stores: `-StorePath` (DMARC Aggregate / TLS-RPT Reports / Registration drift).
- Output formats: HTML/Word/Excel/PDF (basic)/Markdown/MarkdownHtml/JSON (availability varies by cmdlet).

## Alternatives
If you don't need to automate the process, or if you just want to quickly query for your domain name, you can use the following web based tools:

- [MXToolbox](https://mxtoolbox.com/)
- [DNSChecker](https://dnschecker.org/)
- [DNSStuff](https://www.dnsstuff.com/)
- [Dmarcian](https://dmarcian.com/)
- [DMARC Analyzer](https://www.dmarcanalyzer.com/)
- [DKIM Validator](https://dkimvalidator.com/)
- [DKIM Core](https://www.dkimcore.org/tools/)

## Continuous Integration

This project uses GitHub Actions to run .NET and PowerShell tests on Windows, Linux and macOS.
Code coverage results are published to [Codecov](https://codecov.io/gh/EvotecIT/DomainDetective).

## Understanding Results

Project status: pre-release; some checks are under active development. For gaps and current limitations see issues:
https://github.com/EvotecIT/DomainDetective/issues?q=sort%3Aupdated-desc+is%3Aissue+is%3Aopen

We welcome feedback, PRs, and ideas to improve coverage and reporting.

Each analysis type returns an object exposing properties that map to fields described in the relevant RFCs. For example, SPF checks follow [RFC&nbsp;7208](https://datatracker.ietf.org/doc/html/rfc7208) and DMARC analysis references [RFC&nbsp;7489](https://datatracker.ietf.org/doc/html/rfc7489). DKIM validations follow [RFC&nbsp;6376](https://datatracker.ietf.org/doc/html/rfc6376) and enforce RSA public keys of at least 1024&nbsp;bits. DKIM analysis also sets `WeakKey` when the RSA key is shorter than 2048&nbsp;bits. DANE TLSA lookups follow [RFC&nbsp;6698](https://datatracker.ietf.org/doc/html/rfc6698). SMIMEA records are parsed according to [RFC&nbsp;8162](https://www.rfc-editor.org/rfc/rfc8162).

Boolean fields indicate whether a particular requirement was met. You can inspect the object returned from `DomainHealthCheck` or the PowerShell cmdlets to review these properties and make decisions in automation.

`SpfAnalysis` exposes additional collections capturing every token discovered through nested `include` and `redirect` records. These `Resolved*` lists mirror the top-level properties but aggregate results from the entire chain (for example `ResolvedARecords`, `ResolvedMxRecords`, `ResolvedIpv4Records` and `ResolvedIpv6Records`).

DNS lookup counting adheres to [RFC&nbsp;7208](https://datatracker.ietf.org/doc/html/rfc7208) Section&nbsp;4.6.4. Queries caused by the `include`, `a`, `mx`, `ptr`, and `exists` mechanisms as well as the `redirect` modifier are tallied, and exceeding ten during evaluation sets `ExceedsDnsLookups`.

WHOIS analysis surfaces the expiration date and whether the registrar lock is enabled. `DomainSummary` exposes these fields so you can monitor upcoming renewals:

```csharp
var health = new DomainHealthCheck();
await health.Verify("example.com");
var summary = health.BuildSummary();
Console.WriteLine($"Expires on: {summary.ExpiryDate}");
Console.WriteLine($"Registrar lock: {summary.RegistrarLocked}");
Console.WriteLine($"Is public suffix: {summary.IsPublicSuffix}");
```

WHOIS snapshots can be stored by specifying a snapshot directory when running the CLI or PowerShell cmdlet (`-SnapshotPath`). Comparing the latest data to the previous snapshot (`-Diff`) highlights registrar changes. Querying once a day is typically sufficient for monitoring purposes and avoids unnecessary load on WHOIS servers.

For unified WHOIS/RDAP snapshots and structured drift (registrar, status codes, nameservers) that can be embedded in Word/HTML exports, use the time-series store:

```
Import-DDRegistrationSnapshot -DomainName example.com -StorePath .\\Store
Get-DDRegistrationDrift       -DomainName example.com -StorePath .\\Store
```

## Check Descriptions

Human-friendly descriptions for each health check are stored in `CheckDescriptions.cs`. The CLI and any report generators look up a `CheckDescription` by `HealthCheckType` to display its summary, RFC link and remediation steps. You can extend or override these mappings by creating additional entries before generating output.
## Multi-Resolver DNS Override

- C# (FirstSuccess across Cloudflare + Google)

```
using System.Threading.Tasks;
using DnsClientX;

var hc = new DomainDetective.DomainHealthCheck();
// Try Cloudflare wire-format, then Google; return the first useful answer
hc.DnsEndpoints.Add(DnsEndpoint.CloudflareWireFormat);
hc.DnsEndpoints.Add(DnsEndpoint.Google);
hc.MultiResolverStrategy = DomainDetective.MultiResolverStrategy.FirstSuccess;

await hc.Verify("example.com", new[]{ DomainDetective.HealthCheckType.SPF, DomainDetective.HealthCheckType.DNSSEC });

System.Console.WriteLine($"SPF present: {hc.SpfAnalysis.SpfRecordExists}; DS count: {hc.DnsSecAnalysis.DsRecords.Count}");
```

- PowerShell (direct, no functions; edit $Domain)

```
Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$Domain = 'evotec.pl'
$Resolvers = @(
  [DnsClientX.DnsEndpoint]::CloudflareWireFormat,
  [DnsClientX.DnsEndpoint]::Google
)

Test-DDDomainOverallHealth -DomainName $Domain -DnsEndpoints $Resolvers -MultiResolverStrategy FirstSuccess -ExportFormat Word -ExportPath "$PSScriptRoot\Reports" -OpenReport
```

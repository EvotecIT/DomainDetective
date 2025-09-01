[![.NET Tests](https://github.com/EvotecIT/DomainDetective/actions/workflows/dotnet-tests.yml/badge.svg)](https://github.com/EvotecIT/DomainDetective/actions/workflows/dotnet-tests.yml)
[![PowerShell Tests](https://github.com/EvotecIT/DomainDetective/actions/workflows/powershell-tests.yml/badge.svg)](https://github.com/EvotecIT/DomainDetective/actions/workflows/powershell-tests.yml)
[![codecov](https://codecov.io/gh/EvotecIT/DomainDetective/branch/master/graph/badge.svg)](https://codecov.io/gh/EvotecIT/DomainDetective)
[![Discord](https://img.shields.io/discord/508328927853281280?style=flat-square&label=discord%20chat)](https://evo.yt/discord)

Domain Detective is a domain, DNS, and email security auditing toolkit. It ships as:

- C# library: compose and automate checks in .NET
- PowerShell module: fast, scriptable cmdlets with sensible aliases
- CLI: quick interactive and batch workflows

It’s built for automation, reproducibility, and working with sensitive data without depending on web forms.

## Features Overview

- DNS: NS, SOA, Delegation, MX, PTR/Reverse, FCrDNS, DNSSEC chain and DS validation, TTL analysis, EDNS support, wildcard detection, open resolver, zone transfer, DNS propagation (ad-hoc + background monitor)
- Email: SPF, DKIM, DMARC (records + aggregate/forensic parsing), BIMI, MTA-STS policy validation, TLS-RPT import, SMTP STARTTLS and TLS posture, SMTP banner, IMAP/POP3 TLS, open relay
- Web/Certificates: website connectivity, HTTP/2/3, HSTS and security headers, CT/chain details, DANE/TLSA, S/MIMEA
- Reputation & intel: threat intel lookups
- Registry & routing: WHOIS, RDAP, RPKI origin validation
- Reporting & UX: HTML/JSON report generation, interactive CLI wizard

## Available Cmdlets and Aliases

### Email

| Prefixed Name                   | Alias Name               | Purpose                         |
|--------------------------------|--------------------------|---------------------------------|
| `Test-DDEmailArcRecord`        | `Test-EmailArc`          | Validate ARC headers            |
| `Test-DDEmailAutoDiscover`     | `Test-EmailAutoDiscover` | Check mail client discovery     |
| `Test-DDEmailBimiRecord`       | `Test-EmailBimi`         | Verify BIMI record              |
| `Test-DDEmailDkimRecord`       | `Test-EmailDkim`         | Verify DKIM selectors           |
| `Test-DDEmailDmarcRecord`      | `Test-EmailDmarc`        | Verify DMARC policy             |
| `Test-DDEmailSpfRecord`        | `Test-EmailSpf`          | Verify SPF policy               |
| `Test-DDEmailTlsRptRecord`     | `Test-EmailTlsRpt`       | Inspect TLS-RPT                 |
| `Test-DDEmailStartTls`         | `Test-EmailStartTls`     | Check STARTTLS advertisement    |
| `Test-DDEmailSmtpTls`          | `Test-EmailSmtpTls`      | Check SMTP TLS posture          |
| `Test-DDEmailOpenRelay`        | `Test-EmailOpenRelay`    | Detect open SMTP relay          |
| `Get-DDEmailMessageHeaderInfo` | `Get-EmailHeaderInfo`    | Parse raw email headers         |
| `Test-DDEmailLatency`          | `Test-EmailLatency`      | Measure SMTP responsiveness     |
| `Test-DDEmailImapTls`          | `Test-EmailImapTls`      | IMAP TLS check                  |
| `Test-DDEmailPop3Tls`          | `Test-EmailPop3Tls`      | POP3 TLS check                  |
| `Test-DDEmailSmtpBanner`       | `Test-EmailSmtpBanner`   | Inspect SMTP banner             |
| `Test-DDDmarcAggregate`        | `Test-EmailDmarcAggregate` | Parse DMARC aggregate reports |
| `New-DDDmarcRecord`            | `New-DmarcRecord`        | Build DMARC record              |

### Web

| Prefixed Name             | Alias Name            | Purpose                                      |
|---------------------------|-----------------------|----------------------------------------------|
| `Test-DDWebsite`          | `Test-Website`        | Combined website check (cert + HTTPS security)|
| `Test-DDWebsiteSecurity`  | `Test-WebsiteSecurity`| HTTPS security headers + mixed content        |
| `Test-DDDomainCertificate`| `Test-DomainCertificate` | Website certificate incl. TLS grade       |

### DNS

| Prefixed Name                   | Alias Name               | Purpose                         |
|--------------------------------|--------------------------|---------------------------------|
| `Test-DDDnsCaaRecord`          | `Test-DnsCaa`            | Verify CAA                      |
| `Test-DDDnsNsRecord`           | `Test-DnsNs`             | Verify NS                       |
| `Test-DDDnsSoaRecord`          | `Test-DnsSoa`            | Verify SOA                      |
| `Test-DDDnsSecStatus`          | `Test-DnsSec`            | Verify DNSSEC                   |
| `Test-DDDnsBlacklist`          | `Test-DnsBlacklist`      | Check DNSBL (domain + MX IPs)   |
| `Test-DDDnsOpenResolver`       | `Test-DnsOpenResolver`   | Detect open resolver            |
| `Test-DDDnsDanglingCname`      | `Test-DnsDanglingCname`  | Find dangling CNAME             |
| `Test-DDDnsPropagation`        | `Test-DnsPropagation`    | Check global propagation        |
| `Start-DDDnsPropagationMonitor`| `Start-DnsPropagationMonitor` | Background propagation monitor |
| `Stop-DDDnsPropagationMonitor` | `Stop-DnsPropagationMonitor`  | Stop propagation monitor       |
| `Test-DDDnsTtl`                | `Test-DnsTtl`            | TTL analysis                    |
| `Test-DDDnsTunneling`          | `Test-DnsTunneling`      | Detect DNS tunneling (logs)     |
| `Test-DDDnsWildcard`           | `Test-DnsWildcard`       | Detect wildcard catch-all       |
| `Test-DDDnsEdnsSupport`        | `Test-DnsEdnsSupport`    | EDNS support                    |
| `Test-DDDnsHealth`             | `Test-DnsHealth`         | Authoritative SOA/apex/TTL consistency |
| `Test-DDDnsSmimeaRecord`       | `Test-DnsSmimea`         | S/MIMEA                         |
| `Test-DDDnsForwardReverse`     | `Test-DnsFcrDns`         | FCrDNS                          |
| `Test-DDDnsMxRecord`           | `Test-DnsMx`             | MX records                      |
| `Test-DDDnsDelegation`         | `Test-DnsDelegation`     | Parent NS/glue consistency      |
| `Test-DDDnsReverseDns`         | `Test-DnsReverseDns`     | Reverse DNS                     |
| `Test-DDDnsZoneTransfer`       | `Test-DnsZoneTransfer`   | AXFR exposure                   |

### Domain

| Prefixed Name                   | Alias Name               | Purpose                         |
|--------------------------------|--------------------------|---------------------------------|
| `Test-DDDomainContactRecord`   | `Test-DomainContact`     | WHOIS contact sanity            |
| `Test-DDDomainSecurityTxt`     | `Test-DomainSecurityTxt` | security.txt checks             |
| `Test-DDDomainCertificate`     | `Test-DomainCertificate` | Website certificate checks      |
| `Test-DDDomainOverallHealth`   | `Test-DomainHealth`      | Composite health; -Summary returns DomainSummary; -Export* for reports |
| `Get-DDDomainWhois`            | `Get-DomainWhois`        | WHOIS                           |
| `Get-DDDomainFlattenedSpfIp`   | `Get-DomainFlattenedSpfIp` | Flatten SPF to IPs            |
| `Test-DDDomainThreatIntel`     | `Test-DomainThreatIntel` | Threat intel lookups            |
| `Get-DDRdap`                   | `Get-Rdap`               | RDAP                            |
| `Get-DDRdapObject`             | `Get-RdapObject`         | RDAP raw object                 |
| `Get-DDSearchEngineInfo`       | `Get-SearchEngineInfo`   | Search engine queries           |

### TLS & Networking

| Prefixed Name                   | Alias Name               | Purpose                         |
|--------------------------------|--------------------------|---------------------------------|
| `Test-DDTlsDaneRecord`         | `Test-TlsDane`           | DANE/TLSA                       |
| `Get-DDTlsCertificateInfo`     | `Get-CertificateInfo`    | Parse PEM/DER certs             |
| `Test-DDNetworkIpNeighbor`     | `Test-NetworkIpNeighbor` | IP neighbors (add -IncludeMX for mail IPs) |
| `Test-DDNetworkPortAvailability` | `Test-NetworkPortAvailability` | Port scanning              |

### Configuration & Data

| Prefixed Name                | Alias Name           | Purpose                         |
|------------------------------|----------------------|---------------------------------|
| `Add-DDDnsblProvider`        | `Add-DnsblProvider`  | Manage DNSBL                    |
| `Remove-DDDnsblProvider`     | `Remove-DnsblProvider` | Manage DNSBL                  |
| `Clear-DDDnsblProviderList`  | `Clear-DnsblProvider` | Manage DNSBL                  |
| `Import-DDDnsblConfig`       | `Import-DnsblConfig` | Manage DNSBL                    |
| `Import-DDDmarcReport`       | `Import-DmarcReport` | DMARC aggregate zip             |
| `Import-DDDmarcForensic`     | `Import-DmarcForensic` | DMARC forensic zip            |
| `Import-DDEmailTlsRpt`       | `Import-EmailTlsRpt` | TLS-RPT JSON                    |

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
ddcli example.com --checks autodiscover
ddcli example.com --subdomain-policy
ddcli example.com --checks fcrdns
ddcli TestSMIMEA user@example.com
ddcli DnsPropagation --domain example.com --record-type A

 ddcli example.com --check-web
 ddcli example.com --checks DNSHEALTH
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

<!-- Tables moved to top under "Available Cmdlets and Aliases" -->

## Configuration knobs (common)

- Dns endpoint: most cmdlets accept `-DnsEndpoint` to control resolution.
- Scope selection: DNS propagation supports `-Country`, `-Location`, `-Take` and background monitor with start/stop cmdlets.
- Snapshots and diffs: `-SnapshotPath` and `-Diff` compare against stored snapshots.
- Output formats: report tooling supports HTML/Word/Excel/PDF/JSON (work-in-progress where noted).

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

WHOIS snapshots can be stored by specifying a snapshot directory when running the CLI or PowerShell cmdlet. Comparing the latest data to the previous snapshot highlights registrar changes. Querying once a day is typically sufficient for monitoring purposes and avoids unnecessary load on WHOIS servers.

## Check Descriptions

Human-friendly descriptions for each health check are stored in `CheckDescriptions.cs`. The CLI and any report generators look up a `CheckDescription` by `HealthCheckType` to display its summary, RFC link and remediation steps. You can extend or override these mappings by creating additional entries before generating output.

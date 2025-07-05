[![.NET Tests](https://github.com/EvotecIT/DomainDetective/actions/workflows/dotnet-tests.yml/badge.svg)](https://github.com/EvotecIT/DomainDetective/actions/workflows/dotnet-tests.yml)
[![PowerShell Tests](https://github.com/EvotecIT/DomainDetective/actions/workflows/powershell-tests.yml/badge.svg)](https://github.com/EvotecIT/DomainDetective/actions/workflows/powershell-tests.yml)
[![codecov](https://codecov.io/gh/EvotecIT/DomainDetective/branch/master/graph/badge.svg)](https://codecov.io/gh/EvotecIT/DomainDetective)

Domain Detective is a C# library, Tool and PowerShell module in one project. It is designed to help you find interesting information about a domain name.
While there are plenty of tools on the internet that can do this, most of them are web based and require you to enter the domain name into a web form.
This is not ideal if you want to automate the process or if you are working with sensitive information.

Current capabilities include:
- [x] Verify SPF
- [x] Verify DMARC
- [x] Verify DKIM
- [x] Verify CAA
- [x] Verify NS Records
- [x] Verify Delegation (parent NS and glue consistency)
- [x] Verify SOA Records
- [x] Verify MX Records
- [x] Verify reverse DNS (PTR)
- [x] Verify forward-confirmed reverse DNS (FCrDNS)
- [x] Verify DNSSEC
- [x] Follow the delegation chain and validate DS records
- [x] Summarize DNSSEC mismatches across the chain
- [x] Map DNSSEC algorithm numbers to names per RFC 4034
- [x] Analyze DNS TTL
- [x] Validate ARC headers
 - [x] Verify DANE/TLSA (queries `_tcp` or `_udp` names, HTTPS on port 443 by default)
- [x] Query S/MIMEA records
- [x] Verify STARTTLS (detect advertisement downgrades)
- [x] Verify MTA-STS
- [x] Verify SMTP TLS
- [x] Verify IMAP TLS
- [x] Verify POP3 TLS
- [x] Verify SMTP Banner
- [x] Verify TLS-RPT
- [x] Verify BIMI
- [x] Check for dangling CNAME records
- [x] Detect CNAME flattening services (e.g., Cloudflare)
- [x] Verify Autodiscover
- [x] Verify Website Connectivity
  - [x] Verify HTTP/2
  - [x] Verify HTTP/3
  - [x] Verify Certificate
  - [x] Verify Response Time
  - [x] Verify Headers
  - [x] Verify HTTP Security Headers (CSP, Referrer-Policy, X-Frame-Options, Permissions-Policy, Origin-Agent-Cluster)
  - [x] Verify HSTS
  - [x] Verify HPKP
- [x] Verify SecurityTXT
- [x] Verify Open Relay (SMTP)
- [x] Verify Blacklist (DNSBL)
- [x] List IP neighbors via reverse/passive DNS
- [x] Detect DNS tunneling from logs
- [x] Detect wildcard DNS catch-all
- [x] Verify EDNS support
- [x] Scan TCP/UDP ports for a host
- [x] Check propagation of DNS records across the world/country/company
- [x] Verify WHOIS
- [ ] Other things that I haven't thought of yet

### DNSBL Configuration
DNSBL lists used for blacklist checks can be customized. `DNSBLAnalysis` comes with a built-in list, but you can modify it at runtime. Each list entry exposes `Domain`, `Enabled`, and `Comment` fields. Use the following methods on `DNSBLAnalysis` to manage the list:

- `AddDNSBL`/`AddDNSBL(IEnumerable<string>)`
- `RemoveDNSBL`
- `ClearDNSBL`
- `LoadDNSBL`

You can load a custom list from a file using `LoadDNSBL`. Additionally, JSON files describing DNSBL providers can be imported with `ImportDnsblConfig`.

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

### Verifying Website Certificates
`VerifyWebsiteCertificate` can be called with or without a URL scheme. When the scheme is omitted, `https://` is used automatically before checking the certificate.

The `CertificateAnalysis` result now includes:

- `KeyAlgorithm` and `KeySize` for the leaf certificate.
- `WeakKey` when the key is under 2048 bits.
- `Sha1Signature` when the certificate uses SHA‑1.
- `IsSelfSigned` when the certificate subject equals the issuer and the chain length is one.
- With `CaptureTlsDetails` enabled, `TlsProtocol`, `CipherAlgorithm` and `CipherStrength` describe the negotiated cipher-suite.
- `PresentInCtLogs` when the certificate appears in public CT logs.
- `CtLogApiTemplates` allows customizing the list of CT log APIs queried.

### DKIM Analysis
`DkimRecordAnalysis` exposes several indicators:

- `WeakKey` when the RSA key is under 2048 bits.
- `OldKey` when the creation date is over 12 months old.
- `DeprecatedTags` listing tags such as `g` or `h=sha1`.

### Verifying SMTP TLS
`SMTPTLSAnalysis` now stores the negotiated certificate and reports expiration
details and chain validity for each server.

### HTTP Security Headers
`HttpAnalysis.DefaultSecurityHeaders` lists security headers that are inspected when header collection is enabled. The list includes `Content-Security-Policy`, `Referrer-Policy`, `X-Frame-Options`, `Permissions-Policy`, `Origin-Agent-Cluster` and several Cross-Origin policies. You can modify the list to capture additional headers.
`HttpAnalysis` also sets `HstsPreloaded` when the host is found in the bundled HSTS preload list.


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

### Command Line Example

Run the `DomainDetective.Example` project to check a domain. Use `--json` to output
all analysis details in JSON format:

```bash
dotnet run --project DomainDetective.Example example.com --json
```
To verify Autodiscover records only:
```bash
ddcli example.com --checks autodiscover
```
Check DMARC subdomain policy:
```bash
ddcli example.com --subdomain-policy
```
Check forward-confirmed reverse DNS:
```bash
ddcli example.com --checks fcrdns
```
Query an S/MIMEA record:
```bash
ddcli TestSMIMEA user@example.com
```
Check DNS propagation:
```bash
ddcli DnsPropagation --domain example.com --record-type A
```
Progress is displayed as each resolver responds.

### Interactive CLI Wizard

Run `ddcli` without parameters to launch an interactive wizard. It guides you
through entering domain names, selecting checks and choosing between JSON output
or a condensed summary. The wizard is built with **Spectre.Console** for a more
pleasant terminal experience.

### Analyze Message Headers

Parse email headers from a file or raw string:

```bash
ddcli AnalyzeMessageHeader --file ./headers.txt --json
```

### Analyze ARC Headers

Validate an ARC chain from raw headers:

```bash
ddcli AnalyzeARC --file ./headers.txt --json
```

### PowerShell Module

Import the module and call any of the testing cmdlets:

```powershell
Import-Module ./Module/DomainDetective.psd1 -Force
Test-SpfRecord -DomainName "example.com"
Test-Autodiscover -DomainName "example.com"
Test-FCrDns -DomainName "example.com"
```

Analyze TTL values:

```powershell
Test-DnsTtl -DomainName "example.com"
```

Check wildcard DNS:

```powershell
Test-WildcardDns -DomainName "example.com"
```

Check EDNS support:

```powershell
Test-EdnsSupport -DomainName "example.com"
```
Query an S/MIMEA record:
```powershell
Test-SmimeaRecord -EmailAddress "user@example.com"
```

Analyze ARC headers from PowerShell:

```powershell
Get-Content './headers.txt' -Raw | Test-Arc
```

### MTA-STS

`VerifyMTASTS` now validates the `_mta-sts.<domain>` TXT record before downloading
the policy file. If the DNS record is missing or does not contain both `v=STSv1`
and a valid `id` value, the analysis fails. The parsed identifier is exposed via
`PolicyId` and the properties `DnsRecordPresent` and `DnsRecordValid` reflect the
DNS state.

Policy downloads are cached for one hour. Use `CacheDuration` to adjust or call
`ClearCache()` to reset the cache.

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

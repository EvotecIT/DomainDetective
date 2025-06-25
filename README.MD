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
- [x] Verify SOA Records
- [x] Verify MX Records
- [x] Verify DNSSEC
- [x] Verify DANE/TLSA
- [x] Verify STARTTLS
- [x] Verify MTA-STS
- [x] Verify SMTP TLS
- [x] Verify TLS-RPT
- [x] Verify BIMI
- [x] Verify Website Connectivity
  - [x] Verify HTTP/2
  - [x] Verify HTTP/3
  - [x] Verify Certificate
  - [x] Verify Response Time
  - [x] Verify Headers
  - [x] Verify HSTS
  - [x] Verify HPKP
- [x] Verify SecurityTXT
- [x] Verify Open Relay (SMTP)
- [x] Verify Blacklist (DNSBL)
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

### Interactive CLI Wizard

Run `ddcli` without parameters to launch an interactive wizard. It guides you
through entering domain names, selecting checks and choosing between JSON output
or a condensed summary. The wizard is built with **Spectre.Console** for a more
pleasant terminal experience.

### PowerShell Module

Import the module and call any of the testing cmdlets:

```powershell
Import-Module ./Module/DomainDetective.psd1 -Force
Test-SpfRecord -DomainName "example.com"
```

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

Each analysis type returns an object exposing properties that map to fields described in the relevant RFCs. For example, SPF checks follow [RFC&nbsp;7208](https://datatracker.ietf.org/doc/html/rfc7208) and DMARC analysis references [RFC&nbsp;7489](https://datatracker.ietf.org/doc/html/rfc7489). DKIM validations follow [RFC&nbsp;6376](https://datatracker.ietf.org/doc/html/rfc6376) and DANE TLSA lookups follow [RFC&nbsp;6698](https://datatracker.ietf.org/doc/html/rfc6698).

Boolean fields indicate whether a particular requirement was met. You can inspect the object returned from `DomainHealthCheck` or the PowerShell cmdlets to review these properties and make decisions in automation.

`SpfAnalysis` exposes additional collections capturing every token discovered through nested `include` and `redirect` records. These `Resolved*` lists mirror the top-level properties but aggregate results from the entire chain (for example `ResolvedARecords`, `ResolvedMxRecords`, `ResolvedIpv4Records` and `ResolvedIpv6Records`).

DNS lookup counting adheres to [RFC&nbsp;7208](https://datatracker.ietf.org/doc/html/rfc7208) Section&nbsp;4.6.4. Queries caused by the `include`, `a`, `mx`, `ptr`, and `exists` mechanisms as well as the `redirect` modifier are tallied, and exceeding ten during evaluation sets `ExceedsDnsLookups`.

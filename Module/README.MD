# DomainDetective PowerShell Module

Sample usage:

```powershell
Import-Module ./DomainDetective.psd1 -Force
Test-EmailSpf -DomainName "example.com" -Verbose
Test-TlsDane -DomainName "example.com" -Verbose
Test-DnsNs -DomainName "example.com" -Verbose
```

`Test-EmailSpf` returns a `SpfAnalysis` object. Besides the original token lists it now includes `Resolved*` collections that contain tokens discovered while following nested `include` or `redirect` directives.

### Additional cmdlets

- `Test-DnsBlacklist` – queries DNSBL providers for a domain or IP.
  ```powershell
  # Default: domain + MX-IP checks (domain lists + A/AAAA IP blocklists)
  Test-DnsBlacklist -NameOrIpAddress "example.com" -Verbose

  # Force domain-mode explicitly (same effect for domains)
  Test-DnsBlacklist -NameOrIpAddress "example.com" -TreatAsDomain -Verbose

  # Treat as IP-only checks: domains resolve apex A/AAAA, IPs used as-is
  Test-DnsBlacklist -NameOrIpAddress "example.com" -TreatAsIp -Verbose

  # Mixed inputs; only listed results
  Test-DnsBlacklist -NameOrIpAddress "example.com","203.0.113.10" -BlacklistedOnly

  # Full mapping (domain and each IP key)
  $res = Test-DnsBlacklist -NameOrIpAddress "example.com" -FullResponse
  $res["example.com"]

  # Faster resolver: requires DnsClientX 1.0.1+
  Test-DnsBlacklist -NameOrIpAddress "example.com" -MaxConcurrency 64 -Verbose

  Behavior notes:
  - Domains: domain blocklists + resolve MX A/AAAA → query those IPs on IP blocklists.
  - IPs: IP blocklists directly.
  - Mixed arrays: aggregates both without clearing.
  - Fallback: if MX A/AAAA are missing/unresolvable, apex A/AAAA IPs are checked.
  - Use -BlacklistedOnly to filter, -FullResponse to return per-key DNSQueryResult.
  ```
- `Test-EmailDkim` – verifies DKIM selectors for the given domain.
  ```powershell
  Test-EmailDkim -DomainName "example.com" -Selectors "selector1" -Verbose
  ```
- `Test-DnsPropagation` – checks how DNS records propagate across public resolvers. Progress is reported via `Write-Progress`.
  ```powershell
  $file = Join-Path (Split-Path ([System.Reflection.Assembly]::GetExecutingAssembly().Location)) 'Data/DNS/PublicDNS.json'
  Test-DnsPropagation -DomainName "example.com" -RecordType A -ServersFile $file -CompareResults
  ```
- `Test-DnsCaa` – validates CAA entries.
  ```powershell
  Test-DnsCaa -DomainName "example.com"
  ```
- `Test-DomainSecurityTxt` – retrieves security.txt information and reports any issues.
  ```powershell
  Test-DomainSecurityTxt -DomainName "example.com"
  ```
  
- `Test-DDDmarcAggregate` – parse DMARC aggregate reports and summarize failures.
  ```powershell
  # Summarize by reporter organization/email
  Get-ChildItem ./reports/*.xml | Test-DDDmarcAggregate -SummarizeBy Reporter -Deduplicate

  # Summarize by ASN (network enrichment performed automatically)
  Get-ChildItem ./reports/*.xml | Test-DDDmarcAggregate -SummarizeBy Asn -Deduplicate

  # Summarize by country (GeoIP enrichment performed automatically)
  Get-ChildItem ./reports/*.xml | Test-DDDmarcAggregate -SummarizeBy Country -Deduplicate
  ```
- `Test-EmailStartTls` – verifies SMTP STARTTLS support and reports downgrades via `DowngradeDetected`.
  ```powershell
  Test-EmailStartTls -DomainName "example.com" -Port 587 -Verbose
  ```
  To check a specific host use `Test-EmailSmtpTls`.
  ```powershell
  Test-EmailSmtpTls -HostName "mail.example.com" -Port 587
  ```
- `Test-EmailImapTls` / `Test-EmailPop3Tls` – validates TLS on mailbox protocols.
  ```powershell
  Test-EmailImapTls -HostName "imap.example.com" -Port 993
  Test-EmailPop3Tls -HostName "pop.example.com" -Port 995
  ```
- `Test-EmailSmtpBanner` – retrieves and validates SMTP banner.
  ```powershell
  Test-EmailSmtpBanner -HostName "mail.example.com" -Port 25
  ```
- `Test-EmailAutoDiscover` – checks SRV and CNAME records used by mail clients.
  ```powershell
  Test-EmailAutoDiscover -DomainName "example.com"
  ```
- `Test-DnsFcrDns` – validates forward-confirmed reverse DNS (FCrDNS).
  ```powershell
  Test-DnsFcrDns -DomainName "example.com"
  ```
- `Test-DnsMx` – checks MX records.
  ```powershell
  Test-DnsMx -DomainName "example.com"
  ```
- `Import-EmailTlsRpt` – imports TLS-RPT JSON files and summarizes results.
  ```powershell
  Import-EmailTlsRpt -Path "./tlsrpt.json"
  ```
- `Get-CertificateInfo` – parses PEM/DER certificate files and (optionally) shows chain.
  ```powershell
  Get-CertificateInfo -Path "./cert.pem" -ShowChain
  ```
- `Get-EmailHeaderInfo` – parses raw email headers.
  ```powershell
  Get-Content './headers.txt' -Raw | Get-EmailHeaderInfo
  ```
- `Invoke-DomainWizard` – interactive helper that guides through domain checks.
  ```powershell
  Invoke-DomainWizard
  ```
- `Add-DnsblProvider`, `Remove-DnsblProvider`, `Clear-DnsblProvider` and `Import-DnsblConfig` manage the list of DNSBL providers.
  ```powershell
  Add-DnsblProvider -Domain 'dnsbl.example.com' -Comment 'custom'
  Remove-DnsblProvider -Domain 'dnsbl.example.com'
  Clear-DnsblProvider
  Import-DnsblConfig -Path './DnsblProviders.json' -OverwriteExisting
  ```

To execute the PowerShell test suite run:

```powershell
pwsh ./Module/DomainDetective.Tests.ps1
```

### SPF host simulation

```
Test-DDSpfHost -DomainName 'example.com' -IpAddress '192.0.2.10' -Sender 'postmaster@example.com'

# JSON output
Test-DDSpfHost -DomainName 'example.com' -IpAddress '192.0.2.10' -AsJson
```
Outputs an object with `Verdict`, `MatchedType`, `MatchedToken`, `MatchedDomain`, `Chain`, and `DnsLookups`.

### Shaping output (PowerShell objects)

Use standard PowerShell formatting to render concise tables/lists. The cmdlets return rich objects — no custom renderer is required.

Evaluate host (summary table):

```powershell
Test-DDSpfHost -DomainName 'example.com' -IpAddress '192.0.2.10' |
  Format-Table Subject, IpAddress, Verdict, MatchedType, MatchedDomain, DnsLookups, LookupsExceeded
```

SPF provenance (mechanism breakdown) with include/redirect chain:

```powershell
Test-EmailSpf -DomainName 'example.com' |
  Select-Object -Expand Mechanisms |
  Sort-Object Depth, SourceDomain |
  Format-Table Depth, SourceDomain, Type, Prefix, Value, Provider, @{N='Chain';E={$_.Chain -join ' -> '}}
```

JSON shaping when needed:

```powershell
Test-DDSpfHost -DomainName 'example.com' -IpAddress '192.0.2.10' -AsJson | Out-File .\spf-eval.json
```

### Identity (IdP) tenant hints

```powershell
Get-DDIdpInfo -DomainName 'example.com' |
  Format-Table Subject, TenantId, NameSpaceType, FederatedAuthUrl
```
Returns a view object with OIDC discovery URL, TenantId (if found), NameSpaceType and FederatedAuthUrl from GetUserRealm.

## Exporting Reports

All `Test-*` cmdlets share unified `-Export*` switches. Reports are composed from reusable sections (SPF, DKIM, DMARC, DNSBL, MTA‑STS, TLS‑RPT, Mail Classification, …) so content is identical across entry points.

```powershell
# Overall Health (HTML)
Test-DDDomainOverallHealth -DomainName "example.com" -ExportFormat Html -ExportPath ".\Reports\example.html" -OpenReport

# JSON export
Test-DDDomainOverallHealth -DomainName "example.com" -ExportFormat Json -ExportPath ".\Reports\example.json"

# SPF/DKIM/DMARC: multi-domain → single file
Test-DDEmailSpfRecord   -DomainName @('a.com','b.com') -ExportFormat Html -ExportPath ".\Reports" -OpenReport
Test-DDEmailDkimRecord  -DomainName @('a.com','b.com') -Selectors s1,s2 -ExportFormat Word -ExportPath ".\Reports" -OpenReport
Test-DDEmailDmarcRecord -DomainName @('a.com','b.com') -ExportFormat Word -ExportPath ".\Reports" -OpenReport

# Mail Classification (single/multi-domain)
Test-DDMailDomainClassification -DomainName @('contoso.com','fabrikam.com') -ExportFormat Word -ExportPath ".\Reports" -OpenReport
```

Set module-wide export defaults to avoid repeating parameters:

```powershell
# Default to HTML, write to .\Reports, and open in browser
Set-DDExportOptions -DefaultFormat Html -OutputDirectory ".\Reports" -OpenInBrowser:$true -Artifacts:$false -ArtifactsDirectory ".\Artifacts"

# Now you can call without specifying export flags explicitly
Test-DDDomainOverallHealth -DomainName "example.com"
```

Notes:
- `-ExportFormat` supports Html, Word, Excel, Pdf, Json, Markdown, and MarkdownHtml (availability depends on the cmdlet; composition-based exports support Word/Excel/Markdown).
- `-ExportPath` can be a file or a directory. When a directory is provided, a smart filename is generated automatically.
- `-OpenInBrowser` (alias: `-OpenReport`) opens the generated report using the system shell (browser, Word, Excel, etc.).
- Artifacts (scan.json, metrics.json, progress.jsonl, index.jsonl) are optional. Use `-Artifacts` per-call or `Set-DDExportOptions -Artifacts` to enable. Default artifacts path is `./artifacts` unless overridden via `-ArtifactsDirectory` on the cmdlet or `Set-DDExportOptions -ArtifactsDirectory`.

### Composer cmdlet (pipeline-first)

Compose any mix and export one file:

```powershell
$spf   = Test-DDEmailSpfRecord -DomainName 'contoso.com'
$dnsbl = Test-DDDnsBlacklist   -NameOrIpAddress '203.0.113.5'
($spf + $dnsbl) | Export-DDSecurityReport -Scope Detailed -ExportFormat Word -ExportPath .\Reports -OpenReport
```

Inline with a script block:

```powershell
Export-DDSecurityReport -Scope Detailed -ExportFormat Word -ExportPath .\Reports -OpenReport -Compose {
  Test-DDEmailSpfRecord   -DomainName 'contoso.com'
  Test-DDDnsBlacklist     -NameOrIpAddress '203.0.113.5'
  Test-DDMailDomainClassification -DomainName 'contoso.com'
}
```

### Ordering controls

- `-DomainOrder`: `Alphabetical` (default) or `Input` (preserve first-seen order)
- `-SectionOrderMode`: `Canonical` (default), `Input`, or `Custom`
- `-SectionOrder`: explicit list of section keys when using `Custom`

Canonical section order:
MX, SPF, DKIM, DMARC, ARC, BIMI, DNSBL, RPKI, NS, SOA, ZoneTransfer, Wildcard, CAA, Classification, MTA-STS, TLS-RPT, MAILTLS, DNSSEC, DANE.

Executive Summary columns remain canonical across Word/HTML/Markdown/Excel; ordering only affects per-domain section layout.

```powershell
Export-DDSecurityReport -ExportFormat Html -ExportPath .\Reports -DomainOrder Input `
  -SectionOrderMode Custom -SectionOrder SPF,DMARC -OpenReport {
  Test-DDEmailSpfRecord   -DomainName 'contoso.com','fabrikam.com'
  Test-DDEmailDmarcRecord -DomainName 'contoso.com','fabrikam.com'
}
```

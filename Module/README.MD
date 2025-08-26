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

- `Test-DnsBlacklist` – queries DNSBL providers for a domain or IP; for domains it also resolves MX hosts and checks their IPs.
  ```powershell
  Test-DnsBlacklist -NameOrIpAddress "example.com" -Verbose

Flags:
- `-TreatAsDomain`: Force domain-mode (domain lists + MX IPs).
- `-TreatAsIp`: Force IP-mode (only IP DNSBLs; requires IP inputs).
- `-MaxConcurrency`: Resolver concurrency hint (used if supported by DNS client).
- `-BlacklistedOnly`: Return only entries that are listed.
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

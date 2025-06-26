# DomainDetective PowerShell Module

Sample usage:

```powershell
Import-Module ./DomainDetective.psd1 -Force
Test-SpfRecord -DomainName "example.com" -Verbose
Test-DaneRecord -DomainName "example.com" -Verbose
Test-NsRecord -DomainName "example.com" -Verbose
```

`Test-SpfRecord` returns a `SpfAnalysis` object. Besides the original token lists it now includes `Resolved*` collections that contain tokens discovered while following nested `include` or `redirect` directives.

### Additional cmdlets

- `Test-DomainBlacklist` – queries DNSBL providers to determine if a domain or IP address is listed.
  ```powershell
  Test-DomainBlacklist -NameOrIpAddress "example.com" -Verbose
  ```
- `Test-DkimRecord` – verifies DKIM selectors for the given domain.
  ```powershell
  Test-DkimRecord -DomainName "example.com" -Selectors "selector1" -Verbose
  ```
- `Test-DnsPropagation` – checks how DNS records propagate across public resolvers.
  ```powershell
  Test-DnsPropagation -DomainName "example.com" -RecordType A -ServersFile './Data/DNS/PublicDNS.json' -CompareResults
  ```
- `Test-CaaRecord` – validates CAA entries.
  ```powershell
  Test-CaaRecord -DomainName "example.com"
  ```
- `Test-SecurityTXT` – retrieves security.txt information and reports any issues.
  ```powershell
  Test-SecurityTXT -DomainName "example.com"
  ```
- `Test-StartTls` – verifies SMTP STARTTLS support.
  ```powershell
  Test-StartTls -DomainName "example.com" -Port 587 -Verbose
  ```
  To check a specific host use `Test-SmtpTls`.
  ```powershell
  Test-SmtpTls -HostName "mail.example.com" -Port 587
  ```
- `Test-Autodiscover` – checks SRV and CNAME records used by mail clients.
  ```powershell
  Test-Autodiscover -DomainName "example.com"
  ```
- `Test-MessageHeader` – parses raw email headers.
  ```powershell
  Get-Content './headers.txt' -Raw | Test-MessageHeader
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

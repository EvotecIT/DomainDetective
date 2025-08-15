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

- `Test-DnsDomainBlacklist` – queries DNSBL providers to determine if a domain or IP address is listed.
  ```powershell
  Test-DnsDomainBlacklist -NameOrIpAddress "example.com" -Verbose
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
- `Test-EmailAutoDiscover` – checks SRV and CNAME records used by mail clients.
  ```powershell
  Test-EmailAutoDiscover -DomainName "example.com"
  ```
- `Test-DnsFcrDns` – validates forward-confirmed reverse DNS (FCrDNS).
  ```powershell
  Test-DnsFcrDns -DomainName "example.com"
  ```
- `Get-EmailHeaderInfo` – parses raw email headers.
  ```powershell
  Get-Content './headers.txt' -Raw | Get-EmailHeaderInfo
  ```
- `Invoke-DDDomainWizard` – interactive helper that guides through domain checks.
  ```powershell
  Invoke-DDDomainWizard
  ```
- `Add-DnsblProvider`, `Remove-DnsblProvider`, `Clear-DnsblProvider` and `Import-DnsblConfig` manage the list of DNSBL providers.
  ```powershell
  Add-DnsblProvider -Domain 'dnsbl.example.com' -Comment 'custom'
  Remove-DnsblProvider -Domain 'dnsbl.example.com'
  Clear-DnsblProvider
  Import-DnsblConfig -Path './DnsblProviders.json' -OverwriteExisting
  ```

### Prefixed cmdlets

| Cmdlet                          | Legacy Alias               |
|---------------------------------|----------------------------|
| `Get-DDCertificateInfo`         | `Get-CertificateInfo`      |
| `Import-DDTlsRpt`               | `Import-TlsRpt`            |
| `Invoke-DDDomainWizard`         | `Invoke-DomainWizard`      |
| `New-DDDmarcRecord`             | `New-DmarcRecord`          |
| `Start-DDDnsPropagationMonitor` | `Start-DnsPropagationMonitor` |
| `Stop-DDDnsPropagationMonitor`  | `Stop-DnsPropagationMonitor`  |
| `Test-DDDelegation`             | `Test-Delegation`          |
| `Test-DDDmarcAggregate`         | `Test-DmarcAggregate`      |
| `Test-DDImapTls`                | `Test-ImapTls`             |
| `Test-DDPop3Tls`                | `Test-Pop3Tls`             |
| `Test-DDReverseDns`             | `Test-ReverseDns`          |
| `Test-DDSmtpBanner`             | `Test-SmtpBanner`          |
| `Test-DDZoneTransfer`           | `Test-ZoneTransfer`        |

To execute the PowerShell test suite run:

```powershell
pwsh ./Module/DomainDetective.Tests.ps1
```

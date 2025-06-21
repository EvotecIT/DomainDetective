# DomainDetective PowerShell Module

Sample usage:

```powershell
Import-Module ./DomainDetective.psd1 -Force
Test-SpfRecord -DomainName "example.com" -Verbose
Test-DaneRecord -DomainName "example.com" -Verbose
```

To execute the PowerShell test suite run:

```powershell
pwsh ./Module/DomainDetective.Tests.ps1
```

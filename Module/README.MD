# DomainDetective PowerShell Module

Sample usage:

```powershell
Import-Module ./DomainDetective.psd1 -Force
Test-SpfRecord -DomainName "example.com" -Verbose
Test-DaneRecord -DomainName "example.com" -Verbose
Test-NsRecord -DomainName "example.com" -Verbose
```

`Test-SpfRecord` returns a `SpfAnalysis` object. Besides the original token lists it now includes `Resolved*` collections that contain tokens discovered while following nested `include` or `redirect` directives.

To execute the PowerShell test suite run:

```powershell
pwsh ./Module/DomainDetective.Tests.ps1
```

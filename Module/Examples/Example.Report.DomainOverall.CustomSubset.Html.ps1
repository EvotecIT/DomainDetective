Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

# Overall health, but limited to SPF + DNSBL sections
Test-DDDomainOverallHealth -DomainName 'contoso.com' -HealthCheckType SPF,DNSBL -ExportFormat Html -ExportPath "$PSScriptRoot\Reports" -OpenReport


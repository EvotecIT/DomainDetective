Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$domain = 'contoso.com'

Test-DDDomainOverallHealth -DomainName $domain -HealthCheckType MTASTS,TLSRPT -ExportFormat Html -ExportPath "$PSScriptRoot\Reports" -OpenReport


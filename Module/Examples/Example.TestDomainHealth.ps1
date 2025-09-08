# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$Health = Test-DomainHealth -DomainName 'evotec.pl' -Verbose -BrandKeyword 'paypal','google' -ExportFormat Word -ExportPath (Join-Path $PSScriptRoot 'Reports') -OpenReport:$true
$Health | Format-Table
$Health | Format-List

$EmailHealth = Test-DomainHealth -DomainName 'gmail.com' -HealthCheckType SPF, DMARC -ExportFormat Word -ExportPath (Join-Path $PSScriptRoot 'Reports') -OpenReport:$true
$EmailHealth | Format-Table

$DkimHealth = Test-DomainHealth -DomainName 'example.com' -DnsEndpoint System -DkimSelectors 'selector1','selector2' -HealthCheckType DKIM -ExportFormat Word -ExportPath (Join-Path $PSScriptRoot 'Reports') -OpenReport:$true
$DkimHealth | Format-Table

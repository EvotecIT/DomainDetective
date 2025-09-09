Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

# Overall health, but limited to SPF + DNSBL sections
$Output = Test-DDDomainOverallHealth -DomainName 'cyberdrain.com' -ExportFormat Word -ExportPath "$PSScriptRoot\Reports" -OpenReport


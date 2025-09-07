Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force
# Classification-only report composed via pipeline
Get-DDMailDomainClassification -DomainName 'evotec.pl'  |    Export-DDSecurityReport -Scope Minimal -ExportFormat Word -ExportPath "$PSScriptRoot\Reports" -OpenReport


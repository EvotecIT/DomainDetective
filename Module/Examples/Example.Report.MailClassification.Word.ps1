Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

# Classification-only report composed via pipeline
#Test-DDMailDomainClassification -DomainName 'evotec.pl' | Export-DDSecurityReport -Scope Minimal -ExportFormat Word -ExportPath "$PSScriptRoot\Reports" -OpenReport

$Output = Test-DDMailDomainClassification -DomainName 'evotec.pl', 'evotec.xyz' -ExportFormat Word -ExportPath "$PSScriptRoot\Reports" -OpenReport
return

Export-DDSecurityReport -Scope Minimal -ExportFormat Word -ExportPath "$PSScriptRoot\Reports" -OpenReport {
    Test-DDMailDomainClassification -DomainName 'evotec.pl'
}
Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$Output = Test-DDMailDomainClassification -DomainName 'evotec.pl', 'evotec.xyz', 'eurofins.com' -ExportFormat Word, Html,Excel -ExportPath "$PSScriptRoot\Reports" -OpenReport
$Output | Format-List
return

# Classification-only report composed via script block
Export-DDSecurityReport -Scope Minimal -ExportFormat Word -ExportPath "$PSScriptRoot\Reports" -OpenReport {
    Test-DDMailDomainClassification -DomainName 'evotec.pl'
}

return
# Classification-only report composed via pipeline
Test-DDMailDomainClassification -DomainName 'evotec.pl' | Export-DDSecurityReport -Scope Minimal -ExportFormat Word -ExportPath "$PSScriptRoot\Reports" -OpenReport
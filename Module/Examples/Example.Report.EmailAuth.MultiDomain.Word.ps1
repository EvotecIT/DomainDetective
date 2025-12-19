Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$domains = @('evotec.pl', 'evotec.xyz')

$spf = Test-DDEmailSpfRecord -DomainName $domains
$dmarc = Test-DDEmailDmarcRecord -DomainName $domains
$dkim = Test-DDEmailDkimRecord -DomainName $domains -Selectors @('s1', 's2')

($spf + $dmarc + $dkim) | Export-DDSecurityReport -Scope Normal -ExportFormat Word -ExportPath "$PSScriptRoot\Reports" -OpenReport

#($spf) | Export-DDSecurityReport -Scope Normal -ExportFormat Word, Excel, Html -ExportPath "$PSScriptRoot\Reports" -OpenReport
#($spf) | Export-DDSecurityReport -Scope Normal -ExportFormat Html -ExportPath "$PSScriptRoot\Reports" -OpenReport
#($spf) | Export-DDSecurityReport -Scope Normal -ExportFormat Excel -ExportPath "$PSScriptRoot\Reports" -OpenReport

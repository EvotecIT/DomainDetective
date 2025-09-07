Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$domain = 'contoso.com'

$spf   = Test-DDEmailSpfRecord   -DomainName $domain
$dkim  = Test-DDEmailDkimRecord  -DomainName $domain -Selectors @('s1','s2')
$dmarc = Test-DDEmailDmarcRecord -DomainName $domain

# Transport policy related
Test-DDDomainOverallHealth -DomainName $domain -HealthCheckType MTASTS,TLSRPT |    Export-DDSecurityReport -Scope Normal -ExportFormat Word -ExportPath "$PSScriptRoot\Reports" -OpenReport

($spf + $dkim + $dmarc) |    Export-DDSecurityReport -Scope Normal -ExportFormat Word -ExportPath "$PSScriptRoot\Reports" -OpenReport


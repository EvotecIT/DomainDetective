Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$domains = @('contoso.com','fabrikam.com')

$spf   = Test-DDEmailSpfRecord   -DomainName $domains
$dmarc = Test-DDEmailDmarcRecord -DomainName $domains
$dkim  = Test-DDEmailDkimRecord  -DomainName $domains -Selectors @('s1','s2')

($spf + $dmarc + $dkim) |    Export-DDSecurityReport -Scope Normal -ExportFormat Word -ExportPath "$PSScriptRoot\Reports" -OpenReport


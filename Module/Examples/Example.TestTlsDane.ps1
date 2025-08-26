# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

# Show which TLSA names were queried
$Dane1 = Test-TlsDane -DomainName 'evotec.pl' -Verbose
$Dane1.QueriedNames

$Dane2 = Test-TlsDane -DomainName 'ietf.org' -Verbose
$Dane2.QueriedNames

# Probe multiple ports and display parsed records
$Dane3 = Test-TlsDane -DomainName 'ietf.org' -Ports 25,443
$Dane3.QueriedPorts
$Dane3.AnalysisResults | Select-Object DomainName, CertificateUsage, SelectorField, MatchingTypeField, ValidDANERecord | Format-Table -AutoSize


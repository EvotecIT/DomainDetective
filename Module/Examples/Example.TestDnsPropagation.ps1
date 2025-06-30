# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$Results = Test-DnsPropagation -DomainName 'google.com' -RecordType A -CompareResults
$Results | Format-Table

$PublicServers = Test-DnsPropagation -DomainName 'example.com' -RecordType MX -ServersFile (Join-Path $PSScriptRoot '..' 'Data' 'DNS' 'PublicDNS.json')
$PublicServers | Format-Table

$TxtCheck = Test-DnsPropagation -DomainName 'evotec.pl' -RecordType TXT -CompareResults
$TxtCheck | Format-Table

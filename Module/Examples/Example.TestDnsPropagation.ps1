# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$Results = Test-DnsPropagation -DomainName 'google.com' -RecordType A -CompareResults
$Results | Format-Table IPAddress, Country, Location, Records

$PublicServers = Test-DnsPropagation -DomainName 'example.com' -RecordType MX
$PublicServers | Format-Table

$TxtCheck = Test-DnsPropagation -DomainName 'evotec.pl' -RecordType TXT -CompareResults
$TxtCheck | Format-Table

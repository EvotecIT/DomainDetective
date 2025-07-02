# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$Results = Test-DnsPropagation -DomainName 'google.com' -RecordType A -CompareResults
$Results | Format-Table

$File = Join-Path (Split-Path ([System.Reflection.Assembly]::GetExecutingAssembly().Location)) 'Data/DNS/PublicDNS.json'
$PublicServers = Test-DnsPropagation -DomainName 'example.com' -RecordType MX -ServersFile $File
$PublicServers | Format-Table

$TxtCheck = Test-DnsPropagation -DomainName 'evotec.pl' -RecordType TXT -CompareResults
$TxtCheck | Format-Table

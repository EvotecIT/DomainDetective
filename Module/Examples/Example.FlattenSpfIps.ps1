# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$result = Test-EmailSpf -DomainName 'github.com' -Verbose
$result | Format-List
$analysis = $result.FlattenedIpAnalysis
$analysis

# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$results = Test-Rpki -DomainName 'example.com' -Verbose
$results | Format-Table

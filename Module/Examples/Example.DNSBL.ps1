Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$Output = Test-DDDnsBlacklist -NameOrIpAddress 'evotec.pl' -Verbose
$Output | Format-Table
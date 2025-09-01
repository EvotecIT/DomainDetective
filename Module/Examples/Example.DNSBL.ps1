Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$Output = Test-DDDnsBlacklist -NameOrIpAddress 'evotec.pl' -Verbose -BlacklistedOnly
$Output | Format-Table
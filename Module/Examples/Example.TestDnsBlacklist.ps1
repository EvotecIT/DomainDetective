# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

Measure-Command {
    $Blacklists = Test-DnsBlacklist -NameOrIpAddress '89.74.48.96', '8.8.8.8' -Verbose -DnsEndpoint System
    $Blacklists | Sort-Object -Property IsBlackListed, Answer -Descending | Format-Table -AutoSize
}

Measure-Command {
    $Blacklists1 = Test-DnsBlacklist -NameOrIpAddress '89.74.48.96' -Verbose
    $Blacklists1 | Sort-Object -Property IsBlackListed, Answer -Descending | Format-Table -AutoSize
}

Measure-Command {
    $Blacklists2 = Test-DnsBlacklist -NameOrIpAddress '8.8.8.8' -Verbose
    $Blacklists2 | Sort-Object -Property IsBlackListed, Answer -Descending | Format-Table -AutoSize
}

# Domain-driven checks with control over which IPs are resolved
$Dbl = Test-DnsBlacklist -NameOrIpAddress 'evotec.pl' -DomainIpScan MxThenApexFallback -Verbose
$Dbl | Select-Object BlackList,Query,IpAddress,IpSource,SourceHost,IsBlackListed,Answer | Format-Table -AutoSize

# MX-only IP checks
$DblMxOnly = Test-DnsBlacklist -NameOrIpAddress 'evotec.pl' -DomainIpScan MxOnly
$DblMxOnly | Select-Object BlackList,Query,IpAddress,IpSource,SourceHost,IsBlackListed | Format-Table -AutoSize

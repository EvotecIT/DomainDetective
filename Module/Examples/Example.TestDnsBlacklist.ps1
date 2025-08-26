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
    $Blacklists1 = Test-DnsBlacklist -NameOrIpAddress '8.8.8.8' -Verbose
    $Blacklists1 | Sort-Object -Property IsBlackListed, Answer -Descending | Format-Table -AutoSize
}

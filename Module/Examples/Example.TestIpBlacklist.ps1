# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

Measure-Command {
    $Blacklists = Test-DomainBlacklist -NameOrIpAddress 'google.com', "89.74.48.96" -Verbose -DnsEndpoint Cloudflare
    $Blacklists | Sort-Object -Property IsBlackListed, Answer -Descending | Format-Table -AutoSize
}

Measure-Command {
    $Blacklists1 = Test-DomainBlacklist -NameOrIpAddress "89.74.48.96" -Verbose
    $Blacklists1 | Sort-Object -Property IsBlackListed, Answer -Descending | Format-Table -AutoSize
}

Measure-Command {
    $Blacklists1 = Test-DomainBlacklist -NameOrIpAddress 'google.com', "89.74.48.96" -Verbose
    $Blacklists1 | Sort-Object -Property IsBlackListed, Answer -Descending | Format-Table -AutoSize
}

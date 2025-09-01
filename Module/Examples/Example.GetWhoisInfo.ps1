# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$Whois = Get-DDDomainWhois -DomainName 'evotec.pl' -Verbose
$Whois | Format-List

$Example = Get-DDDomainWhois -DomainName 'example.com'
$Example | Format-List

$Idn = Get-DDDomainWhois -DomainName 'xn--bcher-kva.ch'
$Idn | Format-List


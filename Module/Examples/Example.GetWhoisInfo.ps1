# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$Whois = Get-WhoisInfo -DomainName 'evotec.pl' -Verbose
$Whois | Format-List

$Example = Get-WhoisInfo -DomainName 'example.com'
$Example | Format-List

$Idn = Get-WhoisInfo -DomainName 'xn--bcher-kva.ch'
$Idn | Format-List


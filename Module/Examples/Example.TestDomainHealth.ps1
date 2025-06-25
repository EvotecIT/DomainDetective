# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$Health = Test-DomainHealth -DomainName 'evotec.pl' -Verbose
$Health | Format-Table
$Health | Format-List

$EmailHealth = Test-DomainHealth -DomainName 'gmail.com' -HealthCheckType SPF, DMARC
$EmailHealth | Format-Table

$DkimHealth = Test-DomainHealth -DomainName 'example.com' -DnsEndpoint Cloudflare -DkimSelectors 'selector1','selector2' -HealthCheckType DKIM
$DkimHealth | Format-Table

# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$ips = Get-DomainFlattenedSpfIp -DomainName 'github.com' -Verbose
$ips

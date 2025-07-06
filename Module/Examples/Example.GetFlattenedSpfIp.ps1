# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$ips = Get-FlattenedSpfIp -DomainName 'github.com' -Verbose
$ips

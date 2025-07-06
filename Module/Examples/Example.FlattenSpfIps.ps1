# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$result = Test-SpfRecord -DomainName 'github.com' -Verbose
$ips = $result.GetFlattenedIpAddresses('github.com')
$ips

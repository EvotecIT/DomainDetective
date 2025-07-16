# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$domain = Get-RdapObject -Domain 'example.com'
$domain

$ip = Get-RdapObject -Ip '192.0.2.1'
$ip

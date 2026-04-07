Import-Module $PSScriptRoot\..\DnsClientX.psd1 -Force

Get-DnsService -Domain 'example.com'

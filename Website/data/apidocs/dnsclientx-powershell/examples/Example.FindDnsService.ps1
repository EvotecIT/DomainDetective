Import-Module $PSScriptRoot\..\DnsClientX.psd1 -Force

Find-DnsService -Domain 'example.com'

# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$Cert = Test-WebsiteCertificate -Url 'https://evotec.pl' -Verbose
$Cert | Format-List

$Example = Test-WebsiteCertificate -Url 'https://example.com' -ShowChain
$Example | Format-List

# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$Dmarc = Test-EmailDmarc -DomainName 'evotec.pl' -Verbose
$Dmarc | Format-Table
$Dmarc | Format-List

$Health = Test-DomainHealth -DomainName 'evotec.pl' -HealthCheckType DMARC
# Recommendations include successes like enforced policies and reporting addresses.
$Health.Recommendations | Format-Table


$Example = Test-EmailDmarc -DomainName 'example.com'
# Display detailed DMARC analysis for a domain with full enforcement.
$Example | Format-Table
$Example | Format-List

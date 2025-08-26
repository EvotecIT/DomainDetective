Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$DomainOverallHealth = Test-DDDomainOverallHealth -DomainName 'evotec.pl' -Summary -Verbose
$DomainOverallHealth | Format-List
Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$DomainOverallHealth = Test-DDDomainOverallHealth -DomainName 'evotec.pl' -Verbose -ExportFormat Html
$DomainOverallHealth | Format-List

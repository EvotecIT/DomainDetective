Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$DomainOverallHealth = Test-DDDomainOverallHealth -DomainName 'evotec.pl' -Verbose -ExportFormat Html -ExportPath "$PSScriptRoot\Reports"
$DomainOverallHealth | Format-List

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$Domain = 'evotec.pl'

Test-DDDomainOverallHealth -DomainName $Domain -ExportFormat Html -ExportPath "$PSScriptRoot\Reports" -OpenReport


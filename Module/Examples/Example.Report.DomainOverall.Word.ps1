Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$Domain = 'evotec.pl'

Test-DDDomainOverallHealth -DomainName $Domain -ExportFormat Word -ExportPath "$PSScriptRoot\Reports" -OpenReport


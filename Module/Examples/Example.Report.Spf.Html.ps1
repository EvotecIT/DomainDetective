Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$Domain = 'evotec.pl'

Test-DDEmailSpfRecord -DomainName $Domain -ExportFormat Html,Word,Markdown -ExportPath "$PSScriptRoot\Reports" -OpenReport
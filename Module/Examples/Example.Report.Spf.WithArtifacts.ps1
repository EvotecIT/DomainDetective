Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$Domain = 'evotec.pl'

Test-DDEmailSpfRecord -DomainName $Domain -ExportFormat Excel -ExportPath "$PSScriptRoot\Reports" -OpenReport

#Test-DDEmailSpfRecord -DomainName $Domain -ExportFormat Html,Word,Excel -ExportPath "$PSScriptRoot\Reports" -Artifacts -ArtifactsDirectory "$PSScriptRoot\Artifacts" -OpenReport
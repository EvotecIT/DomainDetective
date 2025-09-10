Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$Domain = 'evotec.pl','evotec.xyz'

Test-DDEmailSpfRecord -DomainName $Domain -ExportFormat Html -ExportPath "$PSScriptRoot\Reports" -OpenReport

#Test-DDEmailSpfRecord -DomainName $Domain -ExportFormat Html,Word,Excel -ExportPath "$PSScriptRoot\Reports" -Artifacts -ArtifactsDirectory "$PSScriptRoot\Artifacts" -OpenReport
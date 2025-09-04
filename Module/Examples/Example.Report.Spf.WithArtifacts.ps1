Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$Domain = 'evotec.pl'

Test-DDEmailSpfRecord -DomainName $Domain -ExportFormat Html -ExportPath "$PSScriptRoot\Reports" -Artifacts -ArtifactsDirectory "$PSScriptRoot\Artifacts" -OpenReport
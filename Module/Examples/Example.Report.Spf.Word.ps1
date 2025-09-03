Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$Domain = 'evotec.pl'

# Optional: set defaults once per session
# Set-DDExportOptions -DefaultFormat Word -OutputDirectory $outDir -OpenInBrowser:$true

$Spf = Test-DDEmailSpfRecord -DomainName $Domain -ExportFormat Word -ExportPath "$PSScriptRoot\Reports" -OpenReport
$Spf
Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force
return
$Domain = 'evotec.pl'

# Optional: set defaults once per session
# Set-DDExportOptions -DefaultFormat Word -OutputDirectory $outDir -OpenInBrowser:$true

$Spf = Test-DDEmailSpfRecord -DomainName $Domain -ExportFormat Word -ExportPath "$PSScriptRoot\Reports" -OpenReport
$Spf | Format-List
$Spf.Raw | Format-List
$Spf.Narrative | Format-List
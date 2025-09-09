Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

# Use a single, canonical logo path (fail fast if missing)
$Logo = Join-Path $PSScriptRoot '..\..\Assets\Images\Others\Logo-evotec.png'
if (-not (Test-Path $Logo)) {
    Write-Warning "Logo not found at '$Logo'. Header/footer will render without an image."
}

# Set global export options for branding (header/footer + watermark)
$setDDExportOptionsSplat = @{
    DefaultFormat   = 'Word'
    OutputDirectory = (Join-Path $PSScriptRoot 'Reports')
    OpenInBrowser   = $true
    LogoPath        = $Logo
    HeaderText      = 'Evotec - Email Security'
    WatermarkText   = 'Confidential'
    CompanyName     = 'Evotec'
    CompanyAddress  = 'Katowice, Poland'
    CompanyYear     = (Get-Date).Year
}

Set-DDExportOptions @setDDExportOptionsSplat

$Domain = 'evotec.pl'
$spf = Test-DDEmailSpfRecord -DomainName $Domain
$dmarc = Test-DDEmailDmarcRecord -DomainName $Domain
$mx = Test-DDDnsMxRecord -DomainName $Domain

$spf, $dmarc, $mx | Export-DDSecurityReport -Scope Normal -ExportFormat Word -ExportPath (Join-Path $PSScriptRoot 'Reports') -OpenReport

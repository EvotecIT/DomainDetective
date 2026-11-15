$ErrorActionPreference = 'Stop'

Import-Module -Name (Join-Path $PSScriptRoot '../DomainDetective.psd1')

# Export already collected views to three formats in one request.
$ReportDirectory = Join-Path $PSScriptRoot 'Reports'
$Views = @(
    Test-DDEmailSpfRecord -DomainName 'example.com'
    Test-DDEmailDmarcRecord -DomainName 'example.com'
)
$Views | Export-DDSecurityReport -ExportFormat Word, Pdf, Html -ExportPath $ReportDirectory

# A PDF default applies when a later export omits ExportFormat.
Set-DDExportOptions -DefaultFormat Pdf -OutputDirectory $ReportDirectory
$Views | Export-DDSecurityReport

# Local message analysis can also create all three formats without DNS lookups.
$Headers = "From: sender@example.test`r`nTo: recipient@example.test`r`nSubject: Example report`r`n"
Get-DDEmailMessageHeaderInfo -HeaderText $Headers -ExportFormat Word, Pdf, Html -ExportPath (Join-Path $ReportDirectory 'message-header.docx')

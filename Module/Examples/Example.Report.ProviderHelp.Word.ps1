Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$domain = 'contoso.com'

# Produce input views
$spf = Test-DDEmailSpfRecord -DomainName $domain
$dkim = Test-DDEmailDkimRecord -DomainName $domain -Selectors @('s1', 's2')
$dmarc = Test-DDEmailDmarcRecord -DomainName $domain
$mx = Test-DDDnsMxRecord -DomainName $domain

# 1) Minimal preset — MX-only quick links, no summaries/badges/dates
$spf, $dkim, $dmarc, $mx | Export-DDSecurityReport -Scope Detailed -ExportFormat Word -ExportPath "$PSScriptRoot\Reports" -OpenReport -ProviderHelpPreset Minimal

# 2) Standard preset — default (links + summaries + badges + verified date under MX/SPF/DKIM/DMARC)
$spf, $dkim, $dmarc, $mx | Export-DDSecurityReport -Scope Detailed -ExportFormat Word -ExportPath "$PSScriptRoot\Reports" -OpenReport -ProviderHelpPreset Standard

# 3) Custom override — MX, DKIM, DMARC, BIMI, ARC; topics DMARC, DKIM, SPF, BIMI, ARC; hide dates; exclude login-required docs
$ProviderHelp = @{
    Under             = @('MX', 'DKIM', 'DMARC', 'BIMI', 'ARC')
    Topics            = @('DMARC', 'DKIM', 'SPF', 'BIMI', 'ARC')
    ShowSummaries     = $true
    ShowNotes         = $false
    ShowBadges        = $true
    ShowVerified      = $false
    IncludeRestricted = $false
    IncludeThirdParty = $true
    MaxProviders      = 6
}
$spf, $dkim, $dmarc, $mx | Export-DDSecurityReport -Scope Detailed -ExportFormat Word -ExportPath "$PSScriptRoot\Reports" -OpenReport -ProviderHelpPreset Standard -ProviderHelpOptions $ProviderHelp

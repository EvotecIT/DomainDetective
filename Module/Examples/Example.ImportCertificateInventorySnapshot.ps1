# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$Domains = @(
    'evotec.xyz'
    'evotec.pl'
    'microsoft.com'
    'google.com'
    'eurofins.com'
    'abb.com'
)

$CacheDirectory = Join-Path $PSScriptRoot 'cert-monitor'

$Capture = Import-CertificateInventorySnapshot `
    -DomainName $Domains `
    -CacheDirectory $CacheDirectory `
    -MaxParallelism 24 `
    -DiscoveryParallelism 32 `
    -IncludeImapTls `
    -IncludePop3Tls

$Capture | Format-List

"`nTop captured entries:`n"
$Capture.Snapshot.Entries |
    Select-Object -First 25 Host,Service,Port,CertificateIssuer,CertificateRootIssuer,NotAfterUtc,AuthenticationProfile,AllowsClientAuthentication,ChainComplete |
    Format-Table -AutoSize

"`nInventory summary from persisted snapshots:`n"
Get-CertificateInventorySummary -CacheDirectory $CacheDirectory | Format-List

"`nLikely mTLS / client-auth usage:`n"
Get-CertificateInventoryQuery -CacheDirectory $CacheDirectory -ClientAuthOnly -LatestOnly -MaxResults 100 |
    Select-Object -ExpandProperty Entries |
    Select-Object Host,Service,Port,CertificateSubject,CertificateIssuer,AuthenticationProfile |
    Format-Table -AutoSize

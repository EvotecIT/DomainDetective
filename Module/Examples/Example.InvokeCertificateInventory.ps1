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

$UseNativeCtLogs = $true
$CtParameters = @{}

if ($UseNativeCtLogs) {
    $CtParameters = @{
        EnableNativeCtLogSubdomains         = $true
        NativeCtLogOnly                     = $true
        NativeCtInitialBackfillEntriesPerLog = 5000
        NativeCtCursorStatePath             = (Join-Path $CacheDirectory 'inventory\ct-native-cursor.json')
    }
} else {
    $CtParameters = @{
        CtProfile             = 'Extended'
        EnableShodanCtSource = $true
        ShodanApiKeyEnv       = 'SHODAN_API_KEY'
    }
}

$Capture = Invoke-DDCertificateInventory `
    -DomainName $Domains `
    -CacheDirectory $CacheDirectory `
    -ReuseRecentResults `
    -RecentResultTtlHours 24 `
    -ReprobeExpiringWithinDays 14 `
    -MaxTargets 300 `
    -MaxProbeStartsPerSecond 20 `
    -MaxParallelism 24 `
    -DiscoveryParallelism 32 `
    -IncludeCtSubdomains `
    -VerifyCtSubdomains `
    -IncludeImapTls `
    -IncludePop3Tls `
    @CtParameters

$Capture | Format-List

"`nTop captured entries:`n"
$Capture.Snapshot.Entries |
    Select-Object -First 25 Host,Service,Port,CertificateIssuer,CertificateRootIssuer,NotAfterUtc,AuthenticationProfile,AllowsClientAuthentication,ChainComplete |
    Format-Table -AutoSize

"`nInventory summary from persisted snapshots:`n"
Get-CertificateInventorySummary -CacheDirectory $CacheDirectory | Format-List

"`nLatest raw snapshot metadata:`n"
Get-DDCertificateInventorySnapshot -CacheDirectory $CacheDirectory -Latest -WithoutEntries | Format-List

"`nLikely mTLS / client-auth usage:`n"
Get-CertificateInventoryQuery -CacheDirectory $CacheDirectory -ClientAuthOnly -LatestOnly -MaxResults 100 |
    Select-Object -ExpandProperty Entries |
    Select-Object Host,Service,Port,CertificateSubject,CertificateIssuer,AuthenticationProfile |
    Format-Table -AutoSize

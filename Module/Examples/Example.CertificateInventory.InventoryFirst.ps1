Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$DomainName = @(
    'evotec.xyz'
    'evotec.pl'
    'microsoft.com'
    'google.com'
    'eurofins.com'
    'abb.com'
)

$CacheDirectory = Join-Path $PSScriptRoot 'cert-monitor'
$ArtifactsDirectory = Join-Path $PSScriptRoot 'artifacts'
$null = New-Item -Path $ArtifactsDirectory -ItemType Directory -Force

# Choose CT mode:
# - Native: poll CT logs directly (RFC6962), no crt.sh dependency
# - Public: use default public CT APIs (including crt.sh)
$CtMode = 'Native'

$CtParameters = @{
    IncludeCtSubdomains = $true
    VerifyCtSubdomains  = $true
    MaxCtRowsPerDomain  = 20000
    MaxCtSubdomainsPerDomain = 5000
}

if ($CtMode -eq 'Native') {
    $CtParameters.EnableNativeCtLogSubdomains = $true
    $CtParameters.NativeCtLogOnly = $true
    $CtParameters.NativeCtInitialBackfillEntriesPerLog = 5000
    $CtParameters.NativeCtCursorStatePath = (Join-Path $CacheDirectory 'inventory\ct-native-cursor.json')
}

$Capture = Invoke-DDCertificateInventory `
    -DomainName $DomainName `
    -CacheDirectory $CacheDirectory `
    -ReuseRecentResults `
    -RecentResultTtlHours 24 `
    -ReprobeExpiringWithinDays 14 `
    -MaxTargets 600 `
    -MaxProbeStartsPerSecond 25 `
    -MaxParallelism 24 `
    -DiscoveryParallelism 32 `
    -MaxProbeErrorWarnings 20 `
    -IncludeImapTls `
    -IncludePop3Tls `
    -Verbose `
    @CtParameters

$Capture | Format-List CapturedAtUtc, SnapshotPath, DomainCount, MxHostCount, EntryCount, ValidCount, ExpiredCount, FailedCount

$Query = Get-DDCertificateInventoryQuery `
    -CacheDirectory $CacheDirectory `
    -LatestOnly `
    -MaxResults 200000

$Entries = foreach ($Observed in $Query.Entries) {
    $Observed.Entry
}

$EndpointInventoryPath = Join-Path $ArtifactsDirectory 'certificate-endpoint-inventory.csv'
$Entries |
    Select-Object Host, ResolvedHost, Url, Scheme, Port, Service, CertificateSubject, CertificateIssuer, CertificateIssuerNormalized, CertificateAuthorityFamily, CertificateThumbprint, CertificateSerialNumber, NotBeforeUtc, NotAfterUtc, DaysToExpire, AllowsServerAuthentication, AllowsClientAuthentication, AllowsSecureEmail, ChainComplete, IsReachable, PresentInCtLogs, CertificateChainSource |
    Sort-Object Host, Port, Service |
    Export-Csv -Path $EndpointInventoryPath -NoTypeInformation -Encoding UTF8

$UniqueCertificatesPath = Join-Path $ArtifactsDirectory 'certificate-unique-summary.csv'
$Entries |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_.CertificateThumbprint) } |
    Group-Object -Property CertificateThumbprint |
    ForEach-Object {
        $Sample = $_.Group | Select-Object -First 1
        $DistinctHosts = $_.Group.Host | Sort-Object -Unique
        [pscustomobject] @{
            CertificateThumbprint = $_.Name
            CertificateSerialNumber = $Sample.CertificateSerialNumber
            CertificateSubject = $Sample.CertificateSubject
            CertificateIssuer = $Sample.CertificateIssuer
            CertificateAuthorityFamily = $Sample.CertificateAuthorityFamily
            NotAfterUtc = $Sample.NotAfterUtc
            DaysToExpire = ($_.Group | Measure-Object -Property DaysToExpire -Minimum).Minimum
            EndpointCount = $_.Count
            DistinctHostCount = $DistinctHosts.Count
            Hosts = ($DistinctHosts -join ';')
        }
    } |
    Sort-Object DaysToExpire, EndpointCount -Descending |
    Export-Csv -Path $UniqueCertificatesPath -NoTypeInformation -Encoding UTF8

# Monitoring signal example: detect changes between latest two snapshots.
$Diff = Get-DDCertificateInventoryDiff -CacheDirectory $CacheDirectory -MaxEndpoints 200000
$ChangesPath = Join-Path $ArtifactsDirectory 'certificate-endpoint-changes.csv'
$Diff.Endpoints |
    Where-Object { $_.Status -in @('Added', 'Changed', 'Removed') } |
    Export-Csv -Path $ChangesPath -NoTypeInformation -Encoding UTF8

Write-Host "Endpoint inventory CSV: $EndpointInventoryPath"
Write-Host "Unique certificate CSV: $UniqueCertificatesPath"
Write-Host "Endpoint changes CSV:   $ChangesPath"

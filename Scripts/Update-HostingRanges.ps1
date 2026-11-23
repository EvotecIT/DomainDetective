function Update-HostingRanges {
    <#
    .SYNOPSIS
    Refreshes the published hosting and CDN address ranges bundled with DomainDetective.

    .DESCRIPTION
    Downloads the address ranges that AWS, Google Cloud, Cloudflare, Fastly and Akamai publish
    and writes them to Data/hosting_ranges.tsv.gz, the compact format read by HostingRangeCatalog.
    Each line is: CIDR, provider, kind (Cloud or Cdn), service and region, separated by tabs.
    Lines starting with "as" map an autonomous system number to a provider; they are used only
    when no published range matches. The existing file is replaced only after every source parsed.

    AWS lists most prefixes twice: once as AMAZON and once under the service that uses them.
    Only the service entry is kept for those, so a lookup names EC2, S3 or CloudFront.

    .PARAMETER RepositoryRoot
    Root directory of the DomainDetective repository.

    .EXAMPLE
    .\Scripts\Update-HostingRanges.ps1
    #>
    [CmdletBinding()]
    param(
        [string] $RepositoryRoot = (Split-Path -Parent $PSScriptRoot)
    )

    $sources = [ordered] @{
        Aws        = 'https://ip-ranges.amazonaws.com/ip-ranges.json'
        GoogleCloud = 'https://www.gstatic.com/ipranges/cloud.json'
        CloudflareV4 = 'https://www.cloudflare.com/ips-v4'
        CloudflareV6 = 'https://www.cloudflare.com/ips-v6'
        Fastly     = 'https://api.fastly.com/public-ip-list'
        AkamaiV4   = 'https://techdocs.akamai.com/property-manager/pdfs/akamai_ipv4_CIDRs.txt'
        AkamaiV6   = 'https://techdocs.akamai.com/property-manager/pdfs/akamai_ipv6_CIDRs.txt'
    }
    $outputPath = Join-Path (Join-Path $RepositoryRoot 'Data') 'hosting_ranges.tsv.gz'
    $lines = New-Object System.Collections.Generic.List[string]
    $counts = [ordered] @{}

    function Get-Text([string] $Uri) {
        $content = (Invoke-WebRequest -Uri $Uri -UseBasicParsing).Content
        if ($content -is [byte[]]) {
            $content = [Text.Encoding]::UTF8.GetString($content)
        }
        return [string] $content
    }

    function Get-Cidrs([string] $Text) {
        @($Text -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^[0-9a-fA-F:.]+/\d{1,3}$' })
    }

    function Add-Range([string] $Cidr, [string] $Provider, [string] $Kind, [string] $Service, [string] $Region) {
        $lines.Add(($Cidr, $Provider, $Kind, $Service, $Region) -join "`t")
        if (-not $counts.Contains($Provider)) { $counts[$Provider] = 0 }
        $counts[$Provider]++
    }

    $aws = (Get-Text $sources.Aws) | ConvertFrom-Json
    $awsEntries = @($aws.prefixes | ForEach-Object { [pscustomobject] @{ Cidr = $_.ip_prefix; Service = $_.service; Region = $_.region } }) +
        @($aws.ipv6_prefixes | ForEach-Object { [pscustomobject] @{ Cidr = $_.ipv6_prefix; Service = $_.service; Region = $_.region } })
    if ($awsEntries.Count -lt 1000) { throw 'The AWS range list did not contain the expected prefixes.' }
    foreach ($group in ($awsEntries | Group-Object -Property Cidr)) {
        $specific = @($group.Group | Where-Object { $_.Service -ne 'AMAZON' })
        $chosen = if ($specific.Count -gt 0) { $specific } else { @($group.Group[0]) }
        foreach ($entry in ($chosen | Sort-Object -Property Service -Unique)) {
            $kind = if ($entry.Service -like 'CLOUDFRONT*') { 'Cdn' } else { 'Cloud' }
            $service = if ($entry.Service -eq 'AMAZON') { '' } else { $entry.Service }
            $region = if ($entry.Region -eq 'GLOBAL') { '' } else { $entry.Region }
            Add-Range $entry.Cidr 'Amazon Web Services' $kind $service $region
        }
    }

    $google = (Get-Text $sources.GoogleCloud) | ConvertFrom-Json
    if (@($google.prefixes).Count -lt 100) { throw 'The Google Cloud range list did not contain the expected prefixes.' }
    foreach ($prefix in $google.prefixes) {
        $cidr = if ($prefix.ipv4Prefix) { $prefix.ipv4Prefix } else { $prefix.ipv6Prefix }
        if ($cidr) { Add-Range $cidr 'Google Cloud' 'Cloud' '' $prefix.scope }
    }

    $cloudflare = @(Get-Cidrs (Get-Text $sources.CloudflareV4)) + @(Get-Cidrs (Get-Text $sources.CloudflareV6))
    if ($cloudflare.Count -lt 10) { throw 'The Cloudflare range list did not contain the expected prefixes.' }
    foreach ($cidr in $cloudflare) { Add-Range $cidr 'Cloudflare' 'Cdn' '' '' }

    $fastly = (Get-Text $sources.Fastly) | ConvertFrom-Json
    $fastlyCidrs = @($fastly.addresses) + @($fastly.ipv6_addresses)
    if ($fastlyCidrs.Count -lt 10) { throw 'The Fastly range list did not contain the expected prefixes.' }
    foreach ($cidr in $fastlyCidrs) { Add-Range $cidr 'Fastly' 'Cdn' '' '' }

    $akamai = @(Get-Cidrs (Get-Text $sources.AkamaiV4)) + @(Get-Cidrs (Get-Text $sources.AkamaiV6))
    if ($akamai.Count -lt 3) { throw 'The Akamai range list did not contain the expected prefixes.' }
    foreach ($cidr in $akamai) { Add-Range $cidr 'Akamai' 'Cdn' '' '' }

    # Networks these providers announce. Used only when no published range matches, so it reads as a weaker match.
    $asns = @(
        @('16509', 'Amazon Web Services', 'Cloud'), @('14618', 'Amazon Web Services', 'Cloud'),
        @('15169', 'Google Cloud', 'Cloud'), @('396982', 'Google Cloud', 'Cloud'),
        @('13335', 'Cloudflare', 'Cdn'), @('209242', 'Cloudflare', 'Cdn'),
        @('54113', 'Fastly', 'Cdn'),
        @('20940', 'Akamai', 'Cdn'), @('16625', 'Akamai', 'Cdn'), @('32787', 'Akamai', 'Cdn'), @('63949', 'Akamai', 'Cloud'),
        @('8075', 'Microsoft', 'Cloud')
    )
    foreach ($asn in $asns) {
        $lines.Add(("as$($asn[0])", $asn[1], $asn[2], '', '') -join "`t")
    }

    $header = @(
        "# Published hosting and CDN ranges. Generated by Scripts/Update-HostingRanges.ps1 on $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd'))."
        "# AWS createDate $($aws.createDate); Google Cloud creationTime $($google.creationTime)."
        "# Sources: $(($sources.Values) -join ' ')"
    )
    $payload = (($header + $lines) -join "`n") + "`n"

    $utf8WithoutBom = New-Object Text.UTF8Encoding($false)
    $file = [IO.File]::Create($outputPath)
    try {
        $gzip = New-Object IO.Compression.GZipStream($file, [IO.Compression.CompressionMode]::Compress)
        try {
            $bytes = $utf8WithoutBom.GetBytes($payload)
            $gzip.Write($bytes, 0, $bytes.Length)
        } finally {
            $gzip.Dispose()
        }
    } finally {
        $file.Dispose()
    }

    [pscustomobject] @{
        Ranges = $lines.Count - $asns.Count
        Providers = ($counts.Keys | ForEach-Object { "$_ $($counts[$_])" }) -join ', '
        CompressedBytes = (Get-Item -LiteralPath $outputPath).Length
    }
}

Update-HostingRanges

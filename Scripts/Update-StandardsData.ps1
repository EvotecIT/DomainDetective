function Update-StandardsData {
    <#
    .SYNOPSIS
    Refreshes protocol data snapshots from their authoritative upstream sources.

    .DESCRIPTION
    Downloads the Public Suffix List from publicsuffix.org and transforms Chromium's
    transport security source into the compact gzip HSTS preload format consumed by
    DomainDetective. Existing files are replaced only after both downloads parse.

    .PARAMETER RepositoryRoot
    Root directory of the DomainDetective repository.

    .EXAMPLE
    .\Scripts\Update-StandardsData.ps1
    #>
    [CmdletBinding()]
    param(
        [string] $RepositoryRoot = (Split-Path -Parent $PSScriptRoot)
    )

    $publicSuffixUri = 'https://publicsuffix.org/list/public_suffix_list.dat'
    $chromiumHstsUri = 'https://chromium.googlesource.com/chromium/src/+/refs/heads/main/net/http/transport_security_state_static.json?format=TEXT'
    $dataDirectory = Join-Path $RepositoryRoot 'Data'
    $publicSuffixPath = Join-Path $dataDirectory 'public_suffix_list.dat'
    $hstsPath = Join-Path $dataDirectory 'hsts_preload.json.gz'

    $publicSuffix = (Invoke-WebRequest -Uri $publicSuffixUri -UseBasicParsing).Content
    if ($publicSuffix -notmatch '===BEGIN ICANN DOMAINS===' -or $publicSuffix -notmatch '===END PRIVATE DOMAINS===') {
        throw 'The downloaded Public Suffix List did not contain its expected section markers.'
    }

    $encodedHsts = (Invoke-WebRequest -Uri $chromiumHstsUri -UseBasicParsing).Content.Trim()
    $hstsJson = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encodedHsts))
    $chromiumData = $hstsJson | ConvertFrom-Json
    if ($null -eq $chromiumData.entries -or $chromiumData.entries.Count -lt 1000) {
        throw 'The downloaded Chromium HSTS source did not contain the expected entries.'
    }

    [array] $entries = foreach ($entry in $chromiumData.entries) {
        if ($entry.mode -ne 'force-https' -or [string]::IsNullOrWhiteSpace($entry.name)) {
            continue
        }
        [ordered] @{
            name = $entry.name.ToLowerInvariant()
            includeSubDomains = $entry.include_subdomains -eq $true
        }
    }
    $entries = @($entries | Sort-Object -Property { $_.name } -Unique)
    $payload = [ordered] @{
        source = $chromiumHstsUri
        entries = $entries
    } | ConvertTo-Json -Depth 5 -Compress

    $utf8WithoutBom = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($publicSuffixPath, $publicSuffix, $utf8WithoutBom)
    $file = [IO.File]::Create($hstsPath)
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
        PublicSuffixVersion = ([regex]::Match($publicSuffix, '(?m)^// VERSION: (.+)$')).Groups[1].Value
        HstsEntries = $entries.Count
        HstsCompressedBytes = (Get-Item -LiteralPath $hstsPath).Length
    }
}

Update-StandardsData

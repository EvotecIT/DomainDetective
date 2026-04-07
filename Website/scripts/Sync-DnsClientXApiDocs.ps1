param(
    [string] $SiteRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path,
    [string] $DnsClientXRoot = ''
)

$ErrorActionPreference = 'Stop'

function Resolve-RepoRoot {
    param(
        [string] $SiteRootPath,
        [string] $RequestedRoot
    )

    $candidates = @()
    if (-not [string]::IsNullOrWhiteSpace($RequestedRoot)) {
        $candidates += $RequestedRoot
    }

    $candidates += @(
        (Join-Path $SiteRootPath 'projects\dnsclientx'),
        (Join-Path (Split-Path -Parent $SiteRootPath) 'DnsClientX'),
        'C:\Support\GitHub\DnsClientX',
        '/mnt/c/Support/GitHub/DnsClientX'
    )

    foreach ($candidate in ($candidates | Select-Object -Unique)) {
        if ([string]::IsNullOrWhiteSpace($candidate)) {
            continue
        }

        try {
            $resolved = (Resolve-Path -LiteralPath $candidate -ErrorAction Stop).Path
        } catch {
            continue
        }

        if (Test-Path -LiteralPath (Join-Path $resolved 'DnsClientX.sln') -PathType Leaf) {
            return $resolved
        }
    }

    return $null
}

function Sync-DirectoryContents {
    param(
        [Parameter(Mandatory)]
        [string] $Source,
        [Parameter(Mandatory)]
        [string] $Destination
    )

    New-Item -ItemType Directory -Path $Destination -Force | Out-Null

    $existing = Get-ChildItem -LiteralPath $Destination -Recurse -Force -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending
    foreach ($item in $existing) {
        if ($item.Name -eq '.gitkeep') {
            continue
        }

        Remove-Item -LiteralPath $item.FullName -Force -Recurse -ErrorAction SilentlyContinue
    }

    $sourceItems = Get-ChildItem -LiteralPath $Source -Recurse -Force -ErrorAction SilentlyContinue
    foreach ($item in $sourceItems) {
        $relativePath = [System.IO.Path]::GetRelativePath($Source, $item.FullName)
        if ([string]::IsNullOrWhiteSpace($relativePath) -or $relativePath -eq '.') {
            continue
        }

        $targetPath = Join-Path $Destination $relativePath
        if ($item.PSIsContainer) {
            New-Item -ItemType Directory -Path $targetPath -Force | Out-Null
            continue
        }

        New-Item -ItemType Directory -Path (Split-Path -Parent $targetPath) -Force | Out-Null
        Copy-Item -LiteralPath $item.FullName -Destination $targetPath -Force
    }
}

$resolvedSiteRoot = (Resolve-Path -LiteralPath $SiteRoot).Path
$resolvedRepoRoot = Resolve-RepoRoot -SiteRootPath $resolvedSiteRoot -RequestedRoot $DnsClientXRoot
$targetRoot = Join-Path $resolvedSiteRoot 'data\apidocs\dnsclientx-powershell'
$targetHelpPath = Join-Path $targetRoot 'DnsClientX.PowerShell.dll-Help.xml'
$targetManifestPath = Join-Path $targetRoot 'DnsClientX.psd1'
$targetExamplesPath = Join-Path $targetRoot 'examples'

New-Item -ItemType Directory -Path $targetRoot -Force | Out-Null
New-Item -ItemType Directory -Path $targetExamplesPath -Force | Out-Null

if (-not $resolvedRepoRoot) {
    Write-Host 'DnsClientX repo not found. Keeping checked-in PowerShell API snapshot.' -ForegroundColor Yellow
    return
}

$helpCandidates = @(
    (Join-Path $resolvedRepoRoot 'Module\Artefacts\Unpacked\Modules\DnsClientX\Lib\Core\en-US\DnsClientX.PowerShell.dll-Help.xml'),
    (Join-Path $resolvedRepoRoot 'Module\Artefacts\Unpacked\Modules\DnsClientX\Lib\Default\en-US\DnsClientX.PowerShell.dll-Help.xml'),
    (Join-Path $resolvedRepoRoot 'Module\Lib\Core\en-US\DnsClientX.PowerShell.dll-Help.xml'),
    (Join-Path $resolvedRepoRoot 'Module\Lib\Default\en-US\DnsClientX.PowerShell.dll-Help.xml')
) | Select-Object -Unique

$resolvedHelpPath = $helpCandidates |
    Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
    Select-Object -First 1

if ($resolvedHelpPath) {
    Copy-Item -LiteralPath $resolvedHelpPath -Destination $targetHelpPath -Force
} else {
    Write-Host 'DnsClientX help XML not found in repo artefacts. Keeping checked-in fallback help snapshot.' -ForegroundColor Yellow
}

$manifestCandidates = @(
    (Join-Path $resolvedRepoRoot 'Module\DnsClientX.psd1'),
    (Join-Path $resolvedRepoRoot 'Module\Artefacts\Unpacked\Modules\DnsClientX\DnsClientX.psd1')
) | Select-Object -Unique

$resolvedManifestPath = $manifestCandidates |
    Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
    Select-Object -First 1

if ($resolvedManifestPath) {
    Copy-Item -LiteralPath $resolvedManifestPath -Destination $targetManifestPath -Force
} else {
    Write-Host 'DnsClientX module manifest not found in repo artefacts. Keeping checked-in fallback manifest snapshot.' -ForegroundColor Yellow
}

$sourceExamplesPath = Join-Path $resolvedRepoRoot 'Module\Examples'
if (Test-Path -LiteralPath $sourceExamplesPath -PathType Container) {
    Sync-DirectoryContents -Source $sourceExamplesPath -Destination $targetExamplesPath
} else {
    Write-Host 'DnsClientX PowerShell examples folder not found in repo. Keeping checked-in fallback examples.' -ForegroundColor Yellow
}

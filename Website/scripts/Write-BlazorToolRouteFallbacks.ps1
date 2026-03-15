param(
    [Parameter(Mandatory = $true)]
    [string] $SiteRoot,
    [Parameter(Mandatory = $true)]
    [string] $RegistryPath
)

$ErrorActionPreference = 'Stop'

$resolvedSiteRoot = (Resolve-Path -LiteralPath $SiteRoot).Path
$resolvedRegistryPath = (Resolve-Path -LiteralPath $RegistryPath).Path
$toolsRoot = Join-Path -Path $resolvedSiteRoot -ChildPath 'tools'
$toolsIndexPath = Join-Path -Path $toolsRoot -ChildPath 'index.html'

if (-not (Test-Path -LiteralPath $toolsIndexPath -PathType Leaf)) {
    throw "Tool shell index was not found: $toolsIndexPath"
}

$toolsIndexContent = Get-Content -LiteralPath $toolsIndexPath -Raw
$registryContent = Get-Content -LiteralPath $resolvedRegistryPath -Raw
$slugMatches = [regex]::Matches($registryContent, 'Slug\s*=\s*"(?<slug>[^"]+)"')
[array] $slugs = foreach ($slugMatch in $slugMatches) {
    $slugMatch.Groups['slug'].Value
}
$uniqueSlugs = $slugs | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique

foreach ($slug in $uniqueSlugs) {
    $routeDirectory = Join-Path -Path $toolsRoot -ChildPath $slug
    if (-not (Test-Path -LiteralPath $routeDirectory -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $routeDirectory -Force
    }

    $routeIndexPath = Join-Path -Path $routeDirectory -ChildPath 'index.html'
    Set-Content -LiteralPath $routeIndexPath -Value $toolsIndexContent -Encoding utf8
}

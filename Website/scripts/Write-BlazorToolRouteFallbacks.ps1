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
$baseUrl = 'https://domaindetective.dev'
$defaultPageTitle = 'Domain Detective Browser Tools'
$defaultMetaDescription = 'Browse DomainDetective browser tools for DNS, email, TLS, web security, and threat intelligence checks.'
$defaultLoadingTitle = 'Preparing browser tools'
$defaultLoadingText = 'Loading the shared navigation, theme, and DNS analysis toolkit.'

if (-not (Test-Path -LiteralPath $toolsIndexPath -PathType Leaf)) {
    throw "Tool shell index was not found: $toolsIndexPath"
}

$toolsIndexTemplate = Get-Content -LiteralPath $toolsIndexPath -Raw
$registryContent = Get-Content -LiteralPath $resolvedRegistryPath -Raw
$toolMatches = [regex]::Matches($registryContent, 'new ToolDefinition\s*\{(?<body>.*?)\}', [System.Text.RegularExpressions.RegexOptions]::Singleline)
$toolMetadata = [System.Collections.Generic.Dictionary[string, hashtable]]::new([System.StringComparer]::OrdinalIgnoreCase)

foreach ($toolMatch in $toolMatches) {
    $body = $toolMatch.Groups['body'].Value
    $slugMatch = [regex]::Match($body, 'Slug\s*=\s*"(?<value>[^"]+)"')
    if (-not $slugMatch.Success) {
        continue
    }

    $slug = $slugMatch.Groups['value'].Value
    $nameMatch = [regex]::Match($body, 'Name\s*=\s*"(?<value>[^"]+)"')
    $descriptionMatch = [regex]::Match($body, 'Description\s*=\s*"(?<value>[^"]+)"')
    $toolName = if ($nameMatch.Success) { $nameMatch.Groups['value'].Value } else { $slug }
    $toolDescription = if ($descriptionMatch.Success) { $descriptionMatch.Groups['value'].Value } else { 'Browser-based DomainDetective analysis tool.' }

    $toolMetadata[$slug] = @{
        Slug = $slug
        Name = $toolName
        Description = $toolDescription
    }
}

$toolsIndexContent = $toolsIndexTemplate
$rootReplacements = [ordered] @{
    '__DD_PAGE_TITLE__' = [System.Net.WebUtility]::HtmlEncode($defaultPageTitle)
    '__DD_META_DESCRIPTION__' = [System.Net.WebUtility]::HtmlEncode($defaultMetaDescription)
    '__DD_CANONICAL_URL__' = [System.Net.WebUtility]::HtmlEncode("$baseUrl/tools/")
    '__DD_OG_TITLE__' = [System.Net.WebUtility]::HtmlEncode($defaultPageTitle)
    '__DD_OG_DESCRIPTION__' = [System.Net.WebUtility]::HtmlEncode($defaultMetaDescription)
    '__DD_LOADING_TITLE__' = [System.Net.WebUtility]::HtmlEncode($defaultLoadingTitle)
    '__DD_LOADING_TEXT__' = [System.Net.WebUtility]::HtmlEncode($defaultLoadingText)
}

foreach ($replacement in $rootReplacements.GetEnumerator()) {
    $toolsIndexContent = $toolsIndexContent.Replace($replacement.Key, $replacement.Value)
}

Set-Content -LiteralPath $toolsIndexPath -Value $toolsIndexContent -Encoding utf8

foreach ($tool in $toolMetadata.Values | Sort-Object -Property Slug) {
    $routeDirectory = Join-Path -Path $toolsRoot -ChildPath $tool.Slug
    if (-not (Test-Path -LiteralPath $routeDirectory -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $routeDirectory -Force
    }

    $routeIndexPath = Join-Path -Path $routeDirectory -ChildPath 'index.html'
    $routeTitle = "$($tool.Name) | Domain Detective Tools"
    $routeDescription = $tool.Description
    $routeCanonicalUrl = "$baseUrl/tools/$($tool.Slug)/"
    $routeLoadingTitle = "Preparing $($tool.Name)"
    $routeLoadingText = "Loading the $($tool.Name) workspace and shared DomainDetective browser runtime."

    $routeContent = $toolsIndexTemplate
    $routeReplacements = [ordered] @{
        '__DD_PAGE_TITLE__' = [System.Net.WebUtility]::HtmlEncode($routeTitle)
        '__DD_META_DESCRIPTION__' = [System.Net.WebUtility]::HtmlEncode($routeDescription)
        '__DD_CANONICAL_URL__' = [System.Net.WebUtility]::HtmlEncode($routeCanonicalUrl)
        '__DD_OG_TITLE__' = [System.Net.WebUtility]::HtmlEncode($routeTitle)
        '__DD_OG_DESCRIPTION__' = [System.Net.WebUtility]::HtmlEncode($routeDescription)
        '__DD_LOADING_TITLE__' = [System.Net.WebUtility]::HtmlEncode($routeLoadingTitle)
        '__DD_LOADING_TEXT__' = [System.Net.WebUtility]::HtmlEncode($routeLoadingText)
    }

    foreach ($replacement in $routeReplacements.GetEnumerator()) {
        $routeContent = $routeContent.Replace($replacement.Key, $replacement.Value)
    }

    Set-Content -LiteralPath $routeIndexPath -Value $routeContent -Encoding utf8
}

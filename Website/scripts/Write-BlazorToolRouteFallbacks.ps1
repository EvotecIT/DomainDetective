param(
    [Parameter(Mandatory = $true)]
    [string] $SiteRoot,
    [Parameter(Mandatory = $true)]
    [string] $RegistryPath
)

$ErrorActionPreference = 'Stop'

function Get-ToolDefinitionBodies {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Content
    )

    $marker = 'new ToolDefinition'
    $blocks = New-Object 'System.Collections.Generic.List[string]'
    $searchIndex = 0

    while ($searchIndex -lt $Content.Length) {
        $matchIndex = $Content.IndexOf($marker, $searchIndex, [System.StringComparison]::Ordinal)
        if ($matchIndex -lt 0) {
            break
        }

        $openBraceIndex = $Content.IndexOf('{', $matchIndex)
        if ($openBraceIndex -lt 0) {
            break
        }

        $depth = 0
        $bodyStart = $openBraceIndex + 1
        $inString = $false
        $inVerbatimString = $false
        $escapeNext = $false
        $closed = $false

        for ($i = $openBraceIndex; $i -lt $Content.Length; $i++) {
            $character = $Content[$i]

            if ($inString) {
                if ($inVerbatimString) {
                    if ($character -eq [char]34) {
                        if (($i + 1) -lt $Content.Length -and $Content[$i + 1] -eq [char]34) {
                            $i++
                            continue
                        }

                        $inString = $false
                        $inVerbatimString = $false
                    }

                    continue
                }

                if ($escapeNext) {
                    $escapeNext = $false
                    continue
                }

                if ($character -eq [char]92) {
                    $escapeNext = $true
                    continue
                }

                if ($character -eq [char]34) {
                    $inString = $false
                }

                continue
            }

            if ($character -eq [char]64 -and
                ($i + 1) -lt $Content.Length -and
                $Content[$i + 1] -eq [char]34) {
                $inString = $true
                $inVerbatimString = $true
                $i++
                continue
            }

            if ($character -eq [char]34) {
                $inString = $true
                continue
            }

            if ($character -eq [char]123) {
                $depth++
                continue
            }

            if ($character -eq [char]125) {
                $depth--
                if ($depth -eq 0) {
                    $blocks.Add($Content.Substring($bodyStart, $i - $bodyStart))
                    $searchIndex = $i + 1
                    $closed = $true
                    break
                }
            }
        }

        if (-not $closed) {
            throw "Failed to parse ToolDefinition initializer near index $matchIndex in $resolvedRegistryPath."
        }
    }

    $blocks
}

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
$toolMetadata = [System.Collections.Generic.Dictionary[string, hashtable]]::new([System.StringComparer]::OrdinalIgnoreCase)

foreach ($body in Get-ToolDefinitionBodies -Content $registryContent) {
    $slugMatch = [regex]::Match($body, 'Slug\s*=\s*"(?<value>[^"]+)"')
    if (-not $slugMatch.Success) {
        $previewLength = [Math]::Min(120, $body.Length)
        Write-Warning ("ToolDefinition block found but no Slug could be extracted: {0}" -f $body.Substring(0, $previewLength))
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

if ($toolMetadata.Count -eq 0) {
    throw "No tool metadata was extracted from registry '$resolvedRegistryPath'. Check the file path and ToolDefinition format."
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

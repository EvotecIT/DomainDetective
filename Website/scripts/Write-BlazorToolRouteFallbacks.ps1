param(
    [Parameter(Mandatory = $true)]
    [string] $SiteRoot,
    [Parameter(Mandatory = $true)]
    [string] $RegistryPath,
    [Parameter(Mandatory = $true)]
    [string] $TemplatePath
)

$ErrorActionPreference = 'Stop'

function Get-ToolDefinitionBodies {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Content,
        [Parameter(Mandatory = $true)]
        [string] $SourcePath
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
        $inLineComment = $false
        $inBlockComment = $false
        $escapeNext = $false
        $closed = $false

        for ($i = $openBraceIndex; $i -lt $Content.Length; $i++) {
            $character = $Content[$i]
            $nextCharacter = if (($i + 1) -lt $Content.Length) { $Content[$i + 1] } else { [char]0 }

            if ($inLineComment) {
                if ($character -eq [char]13 -or $character -eq [char]10) {
                    $inLineComment = $false
                }

                continue
            }

            if ($inBlockComment) {
                if ($character -eq [char]42 -and $nextCharacter -eq [char]47) {
                    $inBlockComment = $false
                    $i++
                }

                continue
            }

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

            if ($character -eq [char]47 -and $nextCharacter -eq [char]47) {
                $inLineComment = $true
                $i++
                continue
            }

            if ($character -eq [char]47 -and $nextCharacter -eq [char]42) {
                $inBlockComment = $true
                $i++
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
            throw "Failed to parse ToolDefinition initializer near index $matchIndex in $SourcePath."
        }
    }

    $blocks
}

function Get-CSharpAssignedStringValue {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Content,
        [Parameter(Mandatory = $true)]
        [string] $PropertyName
    )

    $pattern = [string]::Format(
        '(?s)\b{0}\s*=\s*(?<literal>@"(?:[^"]|"")*"|"(?:\\.|[^"\\])*")',
        [regex]::Escape($PropertyName))
    $match = [regex]::Match($Content, $pattern)
    if (-not $match.Success) {
        return $null
    }

    $literal = $match.Groups['literal'].Value
    if ($literal.StartsWith('@"', [System.StringComparison]::Ordinal)) {
        return $literal.Substring(2, $literal.Length - 3).Replace('""', '"')
    }

    [regex]::Unescape($literal.Substring(1, $literal.Length - 2))
}

$resolvedSiteRoot = (Resolve-Path -LiteralPath $SiteRoot).Path
$resolvedRegistryPath = (Resolve-Path -LiteralPath $RegistryPath).Path
$resolvedTemplatePath = (Resolve-Path -LiteralPath $TemplatePath).Path
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

$toolsIndexTemplate = Get-Content -LiteralPath $resolvedTemplatePath -Raw
$registryContent = Get-Content -LiteralPath $resolvedRegistryPath -Raw
$toolMetadata = [System.Collections.Generic.Dictionary[string, hashtable]]::new([System.StringComparer]::OrdinalIgnoreCase)
$requiredTemplateTokens = @(
    '__DD_PAGE_TITLE__',
    '__DD_META_DESCRIPTION__',
    '__DD_CANONICAL_URL__',
    '__DD_OG_TITLE__',
    '__DD_OG_DESCRIPTION__',
    '__DD_LOADING_TITLE__',
    '__DD_LOADING_TEXT__'
)

foreach ($token in $requiredTemplateTokens) {
    if ($toolsIndexTemplate.IndexOf($token, [System.StringComparison]::Ordinal) -lt 0) {
        throw "Template '$resolvedTemplatePath' does not contain required token '$token'."
    }
}

foreach ($body in Get-ToolDefinitionBodies -Content $registryContent -SourcePath $resolvedRegistryPath) {
    $slug = Get-CSharpAssignedStringValue -Content $body -PropertyName 'Slug'
    if ([string]::IsNullOrWhiteSpace($slug)) {
        $previewLength = [Math]::Min(120, $body.Length)
        Write-Warning ("ToolDefinition block found but no Slug could be extracted: {0}" -f $body.Substring(0, $previewLength))
        continue
    }

    $toolName = Get-CSharpAssignedStringValue -Content $body -PropertyName 'Name'
    $toolDescription = Get-CSharpAssignedStringValue -Content $body -PropertyName 'Description'
    if ([string]::IsNullOrWhiteSpace($toolName)) {
        $toolName = $slug
    }
    if ([string]::IsNullOrWhiteSpace($toolDescription)) {
        $toolDescription = 'Browser-based DomainDetective analysis tool.'
    }

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

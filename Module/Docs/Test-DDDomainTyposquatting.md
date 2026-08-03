---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# Test-DDDomainTyposquatting
## SYNOPSIS
Generates and evaluates typosquatting candidates for a domain.

## SYNTAX
### ServerName (Default)
```powershell
Test-DDDomainTyposquatting [-DomainName] <string[]> [[-DnsEndpoint] <DnsEndpoint>] [-ExportFormat <ReportFormat[]>] [-ExportPath <string>] [-OpenInBrowser] [-ExportArtifacts] [-ArtifactsDirectory <string>] [-DisableParallel] [-ThrottleLimit <Int32>] [-MaxParallelism <Int32>] [-DnsParallelism <Int32>] [-DnsEndpoints <DnsEndpoint[]>] [-MultiResolverStrategy <MultiResolverStrategy>] [-MultiResolverMaxParallelism <Int32>] [-BrandKeyword <string[]>] [-DictionaryWord <string[]>] [-AlternativeTld <string[]>] [-LevenshteinThreshold <int>] [-EnableVisualSimilarity] [-EnableBrowserScreenshot] [-VisualMaxCandidates <int>] [-VisualMaxAssetsPerPage <int>] [-EnableSmtpBanner] [-EnableSmtpRecipientAcceptance] [<CommonParameters>]
```

## DESCRIPTION
Part of the DomainDetective project.

## EXAMPLES

### EXAMPLE 1
```powershell
Test-DDDomainTyposquatting -DomainName example.com -BrandKeyword paypal
```


## PARAMETERS

### -AlternativeTld
Alternative TLDs used for TLD swap candidate generation.

```yaml
Type: String[]
Parameter Sets: ServerName
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ArtifactsDirectory
Destination directory for artifacts when emitted.

```yaml
Type: String
Parameter Sets: ServerName
Aliases: ArtifactsPath
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -BrandKeyword
Protected brand terms to combine with the analyzed domain label.

```yaml
Type: String[]
Parameter Sets: ServerName
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DictionaryWord
Additional dictionary words used for candidate generation.

```yaml
Type: String[]
Parameter Sets: ServerName
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DisableParallel
Disable parallel execution for cmdlet-level work.

```yaml
Type: SwitchParameter
Parameter Sets: ServerName
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DnsEndpoint
DNS server used for queries.

```yaml
Type: DnsEndpoint
Parameter Sets: ServerName
Aliases: None
Possible values: System, SystemTcp, Cloudflare, CloudflareSecurity, CloudflareFamily, CloudflareWireFormat, CloudflareWireFormatPost, CloudflareJsonPost, Google, GoogleWireFormat, GoogleWireFormatPost, GoogleJsonPost, Quad9, Quad9ECS, Quad9Unsecure, OpenDNS, OpenDNSFamily, CloudflareQuic, Quad9Http3, Quad9Quic, GoogleQuic, AdGuard, AdGuardFamily, AdGuardNonFiltering, NextDNS, DnsCryptCloudflare, DnsCryptQuad9, DnsCryptRelay, RootServer, CloudflareOdoh, Custom

Required: False
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DnsEndpoints
Optional list of resolver endpoints to use (multi-resolver).

```yaml
Type: DnsEndpoint[]
Parameter Sets: ServerName
Aliases: None
Possible values: System, SystemTcp, Cloudflare, CloudflareSecurity, CloudflareFamily, CloudflareWireFormat, CloudflareWireFormatPost, CloudflareJsonPost, Google, GoogleWireFormat, GoogleWireFormatPost, GoogleJsonPost, Quad9, Quad9ECS, Quad9Unsecure, OpenDNS, OpenDNSFamily, CloudflareQuic, Quad9Http3, Quad9Quic, GoogleQuic, AdGuard, AdGuardFamily, AdGuardNonFiltering, NextDNS, DnsCryptCloudflare, DnsCryptQuad9, DnsCryptRelay, RootServer, CloudflareOdoh, Custom

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DnsParallelism
DNS resolver concurrency hint for health checks.

```yaml
Type: Int32
Parameter Sets: ServerName
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DomainName
Domain(s) to analyze.

```yaml
Type: String[]
Parameter Sets: ServerName
Aliases: None
Possible values:

Required: True
Position: 0
Default value: None
Accept pipeline input: True (ByValue, ByPropertyName)
Accept wildcard characters: False
```

### -EnableBrowserScreenshot
When specified, visual similarity can try a built-in rendered browser screenshot provider.

```yaml
Type: SwitchParameter
Parameter Sets: ServerName
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -EnableSmtpBanner
When specified, candidate MX hosts are checked for responsive SMTP banners.

```yaml
Type: SwitchParameter
Parameter Sets: ServerName
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -EnableSmtpRecipientAcceptance
When specified, candidate MX hosts are probed for recipient acceptance on the lookalike domain.

```yaml
Type: SwitchParameter
Parameter Sets: ServerName
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -EnableVisualSimilarity
When specified, visual similarity uses reusable favicon and social-image fingerprinting.

```yaml
Type: SwitchParameter
Parameter Sets: ServerName
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ExportArtifacts
Emit artifacts (scan.json, metrics.json, progress.jsonl).

```yaml
Type: SwitchParameter
Parameter Sets: ServerName
Aliases: Artifacts
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ExportFormat
Desired export format(s). Accepts one or many values.

```yaml
Type: ReportFormat[]
Parameter Sets: ServerName
Aliases: Report
Possible values: Html, Json, Word, Excel, Markdown, MarkdownHtml

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ExportPath
Output file path for export.

```yaml
Type: String
Parameter Sets: ServerName
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -LevenshteinThreshold
Maximum Levenshtein distance used for edit-distance-based candidate generation.

```yaml
Type: Int32
Parameter Sets: ServerName
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -MaxParallelism
Maximum concurrent health checks within a single domain run.

```yaml
Type: Int32
Parameter Sets: ServerName
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -MultiResolverMaxParallelism
Maximum number of resolvers to query in parallel (null = all).

```yaml
Type: Int32
Parameter Sets: ServerName
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -MultiResolverStrategy
Strategy used when multiple DNS endpoints are provided.

```yaml
Type: MultiResolverStrategy
Parameter Sets: ServerName
Aliases: None
Possible values: FirstSuccess, FastestWins, SequentialFallback, RoundRobin, Random

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -OpenInBrowser
Open export in browser when applicable.

```yaml
Type: SwitchParameter
Parameter Sets: ServerName
Aliases: OpenReport
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ThrottleLimit
Maximum number of concurrent items for cmdlet-level parallel work.

```yaml
Type: Int32
Parameter Sets: ServerName
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -VisualMaxAssetsPerPage
Maximum number of visual assets compared per analyzed page.

```yaml
Type: Int32
Parameter Sets: ServerName
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -VisualMaxCandidates
Maximum number of candidates included in visual similarity comparison.

```yaml
Type: Int32
Parameter Sets: ServerName
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

- `System.String[]`

## OUTPUTS

- `None`

## RELATED LINKS

- None

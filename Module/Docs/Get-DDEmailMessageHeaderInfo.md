---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# Get-DDEmailMessageHeaderInfo
## SYNOPSIS
Parses raw email message headers.

## SYNTAX
### __AllParameterSets
```powershell
Get-DDEmailMessageHeaderInfo [-HeaderText] <string> [-ExpectedMx <string[]>] [-ExportFormat <ReportFormat[]>] [-ExportPath <string>] [-OpenInBrowser] [-ExportArtifacts] [-ArtifactsDirectory <string>] [-DisableParallel] [-ThrottleLimit <Int32>] [-MaxParallelism <Int32>] [-DnsParallelism <Int32>] [-DnsEndpoints <DnsEndpoint[]>] [-MultiResolverStrategy <MultiResolverStrategy>] [-MultiResolverMaxParallelism <Int32>] [<CommonParameters>]
```

## DESCRIPTION
Part of the DomainDetective project.

## EXAMPLES

### EXAMPLE 1
```powershell
Get-Content './headers.txt' -Raw | Get-DDEmailMessageHeaderInfo -ExpectedMx 'mx1.gateway.example.net'
```


## PARAMETERS

### -ArtifactsDirectory
Destination directory for artifacts when emitted.

```yaml
Type: String
Parameter Sets: __AllParameterSets
Aliases: ArtifactsPath
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
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DnsEndpoints
Optional list of resolver endpoints to use (multi-resolver).

```yaml
Type: DnsEndpoint[]
Parameter Sets: __AllParameterSets
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
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ExpectedMx
Expected public MX hosts that should appear in the received path.

```yaml
Type: String[]
Parameter Sets: __AllParameterSets
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
Parameter Sets: __AllParameterSets
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
Parameter Sets: __AllParameterSets
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
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -HeaderText
Raw header text.

```yaml
Type: String
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: True
Position: 0
Default value: None
Accept pipeline input: True (ByValue)
Accept wildcard characters: False
```

### -MaxParallelism
Maximum concurrent health checks within a single domain run.

```yaml
Type: Int32
Parameter Sets: __AllParameterSets
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
Parameter Sets: __AllParameterSets
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
Parameter Sets: __AllParameterSets
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
Parameter Sets: __AllParameterSets
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
Parameter Sets: __AllParameterSets
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

- `System.String`

## OUTPUTS

- `None`

## RELATED LINKS

- None

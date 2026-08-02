---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# Test-DDDesiredState
## SYNOPSIS
Validates domains against an organization-specific desired state baseline.

## SYNTAX
### ByName (Default)
```powershell
Test-DDDesiredState [-DomainName] <string[]> [-DesiredStatePath] <string> [[-DnsEndpoint] <DnsEndpoint>] [-NoClassification] [-DesiredStateMode <DesiredStateMode>] [-FailFast] [-LogEvaluationErrorsAsErrors] [-ExportFormat <ReportFormat[]>] [-ExportPath <string>] [-OpenInBrowser] [-ExportArtifacts] [-ArtifactsDirectory <string>] [-DisableParallel] [-ThrottleLimit <int>] [-MaxParallelism <int>] [-DnsParallelism <int>] [-DnsEndpoints <DnsEndpoint[]>] [-MultiResolverStrategy <MultiResolverStrategy>] [-MultiResolverMaxParallelism <int>] [<CommonParameters>]
```

### ByConfiguration
```powershell
Test-DDDesiredState [-DomainName] <string[]> [-Configuration] <DesiredStateConfiguration> [[-DnsEndpoint] <DnsEndpoint>] [-NoClassification] [-DesiredStateMode <DesiredStateMode>] [-FailFast] [-LogEvaluationErrorsAsErrors] [-ExportFormat <ReportFormat[]>] [-ExportPath <string>] [-OpenInBrowser] [-ExportArtifacts] [-ArtifactsDirectory <string>] [-DisableParallel] [-ThrottleLimit <int>] [-MaxParallelism <int>] [-DnsParallelism <int>] [-DnsEndpoints <DnsEndpoint[]>] [-MultiResolverStrategy <MultiResolverStrategy>] [-MultiResolverMaxParallelism <int>] [<CommonParameters>]
```

## DESCRIPTION
Loads a JSON desired state configuration and evaluates non-conformance for each domain.

## EXAMPLES

### EXAMPLE 1
```powershell
PS> Test-DDDesiredState -DomainName example.com -DesiredStatePath .\desired-state.json
```

Returns desired state conformance results and issues.

## PARAMETERS

### -ArtifactsDirectory
{{ Fill ArtifactsDirectory Description }}

```yaml
Type: String
Parameter Sets: ByName, ByConfiguration
Aliases: ArtifactsPath
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Configuration
In-memory desired state configuration object.

```yaml
Type: DesiredStateConfiguration
Parameter Sets: ByConfiguration
Aliases: None
Possible values:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DesiredStateMode
Controls how desired state and best-practice findings are separated for reporting.

```yaml
Type: Nullable`1
Parameter Sets: ByName, ByConfiguration
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DesiredStatePath
Path to a desired state JSON configuration file.

```yaml
Type: String
Parameter Sets: ByName
Aliases: None
Possible values:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DisableParallel
{{ Fill DisableParallel Description }}

```yaml
Type: SwitchParameter
Parameter Sets: ByName, ByConfiguration
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
Parameter Sets: ByName, ByConfiguration
Aliases: None
Possible values: System, SystemTcp, Cloudflare, CloudflareSecurity, CloudflareFamily, CloudflareWireFormat, CloudflareWireFormatPost, CloudflareJsonPost, Google, GoogleWireFormat, GoogleWireFormatPost, GoogleJsonPost, Quad9, Quad9ECS, Quad9Unsecure, OpenDNS, OpenDNSFamily, CloudflareQuic, Quad9Http3, Quad9Quic, GoogleQuic, AdGuard, AdGuardFamily, AdGuardNonFiltering, NextDNS, DnsCryptCloudflare, DnsCryptQuad9, DnsCryptRelay, RootServer, CloudflareOdoh, Custom

Required: False
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DnsEndpoints
{{ Fill DnsEndpoints Description }}

```yaml
Type: DnsEndpoint[]
Parameter Sets: ByName, ByConfiguration
Aliases: None
Possible values: System, SystemTcp, Cloudflare, CloudflareSecurity, CloudflareFamily, CloudflareWireFormat, CloudflareWireFormatPost, CloudflareJsonPost, Google, GoogleWireFormat, GoogleWireFormatPost, GoogleJsonPost, Quad9, Quad9ECS, Quad9Unsecure, OpenDNS, OpenDNSFamily, CloudflareQuic, Quad9Http3, Quad9Quic, GoogleQuic, AdGuard, AdGuardFamily, AdGuardNonFiltering, NextDNS, DnsCryptCloudflare, DnsCryptQuad9, DnsCryptRelay, RootServer, CloudflareOdoh, Custom

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DnsParallelism
{{ Fill DnsParallelism Description }}

```yaml
Type: Nullable`1
Parameter Sets: ByName, ByConfiguration
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
Parameter Sets: ByName, ByConfiguration
Aliases: None
Possible values:

Required: True
Position: 0
Default value: None
Accept pipeline input: True (ByValue, ByPropertyName)
Accept wildcard characters: False
```

### -ExportArtifacts
{{ Fill ExportArtifacts Description }}

```yaml
Type: SwitchParameter
Parameter Sets: ByName, ByConfiguration
Aliases: Artifacts
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ExportFormat
{{ Fill ExportFormat Description }}

```yaml
Type: ReportFormat[]
Parameter Sets: ByName, ByConfiguration
Aliases: Report
Possible values: Html, Json, Word, Excel, Markdown, MarkdownHtml

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ExportPath
{{ Fill ExportPath Description }}

```yaml
Type: String
Parameter Sets: ByName, ByConfiguration
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -FailFast
When set, throws on evaluation exceptions instead of logging and continuing.

```yaml
Type: SwitchParameter
Parameter Sets: ByName, ByConfiguration
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -LogEvaluationErrorsAsErrors
When set, logs evaluation exceptions as errors instead of warnings.

```yaml
Type: SwitchParameter
Parameter Sets: ByName, ByConfiguration
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -MaxParallelism
{{ Fill MaxParallelism Description }}

```yaml
Type: Nullable`1
Parameter Sets: ByName, ByConfiguration
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -MultiResolverMaxParallelism
{{ Fill MultiResolverMaxParallelism Description }}

```yaml
Type: Nullable`1
Parameter Sets: ByName, ByConfiguration
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -MultiResolverStrategy
{{ Fill MultiResolverStrategy Description }}

```yaml
Type: MultiResolverStrategy
Parameter Sets: ByName, ByConfiguration
Aliases: None
Possible values: FirstSuccess, FastestWins, SequentialFallback, RoundRobin, Random

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -NoClassification
Do not run mail classification even if the baseline contains classification-specific overrides.

```yaml
Type: SwitchParameter
Parameter Sets: ByName, ByConfiguration
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -OpenInBrowser
{{ Fill OpenInBrowser Description }}

```yaml
Type: SwitchParameter
Parameter Sets: ByName, ByConfiguration
Aliases: OpenReport
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ThrottleLimit
{{ Fill ThrottleLimit Description }}

```yaml
Type: Nullable`1
Parameter Sets: ByName, ByConfiguration
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

- `DomainDetective.Views.DesiredStateInfo`

## RELATED LINKS

- None

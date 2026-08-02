---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# Export-DDSecurityReport
## SYNOPSIS
Composes a security report (Word/HTML) from pipeline view objects (SPF/DKIM/DMARC).

## SYNTAX
### Default (Default)
```powershell
Export-DDSecurityReport [[-InputObject] <Object>] [-Scope <ReportScope>] [-ShowInfoFindings] [-ProviderHelpPreset <string>] [-ProviderHelpOptions <hashtable>] [-Title <string>] [-Subject <string>] [-Category <string>] [-Keywords <string>] [-Creator <string>] [-HtmlProfile <string>] [-ExcelProfile <string>] [-DomainOrder <string>] [-SectionOrderMode <string>] [-SectionOrder <string[]>] [-SummaryColumnCap <int>] [-ExportFormat <ReportFormat[]>] [-ExportPath <string>] [-OpenInBrowser] [-ExportArtifacts] [-ArtifactsDirectory <string>] [-DisableParallel] [-ThrottleLimit <int>] [-MaxParallelism <int>] [-DnsParallelism <int>] [-DnsEndpoints <DnsEndpoint[]>] [-MultiResolverStrategy <MultiResolverStrategy>] [-MultiResolverMaxParallelism <int>] [<CommonParameters>]
```

### Inline
```powershell
Export-DDSecurityReport [[-Compose] <scriptblock>] [[-InputObject] <Object>] [-Scope <ReportScope>] [-ShowInfoFindings] [-ProviderHelpPreset <string>] [-ProviderHelpOptions <hashtable>] [-Title <string>] [-Subject <string>] [-Category <string>] [-Keywords <string>] [-Creator <string>] [-HtmlProfile <string>] [-ExcelProfile <string>] [-DomainOrder <string>] [-SectionOrderMode <string>] [-SectionOrder <string[]>] [-SummaryColumnCap <int>] [-ExportFormat <ReportFormat[]>] [-ExportPath <string>] [-OpenInBrowser] [-ExportArtifacts] [-ArtifactsDirectory <string>] [-DisableParallel] [-ThrottleLimit <int>] [-MaxParallelism <int>] [-DnsParallelism <int>] [-DnsEndpoints <DnsEndpoint[]>] [-MultiResolverStrategy <MultiResolverStrategy>] [-MultiResolverMaxParallelism <int>] [<CommonParameters>]
```

## DESCRIPTION
Pipe outputs from existing cmdlets to build one report without duplicating rendering logic.

## EXAMPLES

### EXAMPLE 1
```powershell
Test-DDEmailSpfRecord -DomainName contoso.com, fabrikam.com |
Test-DDEmailDmarcRecord -DomainName contoso.com, fabrikam.com |
Export-DDSecurityReport -ExportFormat Word -ExportPath ".\\Reports" -OpenReport
```


### EXAMPLE 2
```powershell
Export-DDSecurityReport -ExportFormat Markdown -ExportPath ".\\Reports" {
  Test-DDEmailSpfRecord  -DomainName contoso.com,fabrikam.com
  Test-DDEmailDkimRecord -DomainName contoso.com,fabrikam.com
  Test-DDEmailDmarcRecord -DomainName contoso.com,fabrikam.com
}
```


### EXAMPLE 3
```powershell
$views = Test-DDEmailSpfRecord -DomainName contoso.com,fabrikam.com
$views | Export-DDSecurityReport -ExportFormat Markdown -ExportPath ".\\Reports" {
  Test-DDEmailDmarcRecord -DomainName contoso.com,fabrikam.com
}
```


### EXAMPLE 4
```powershell
Export-DDSecurityReport -ExportFormat Html -ExportPath ".\\Reports" -DomainOrder Input `
  -SectionOrderMode Custom -SectionOrder MX,SPF,DMARC {
  Test-DDEmailSpfRecord   -DomainName contoso.com,fabrikam.com
  Test-DDEmailDmarcRecord -DomainName contoso.com,fabrikam.com
}
```


## PARAMETERS

### -ArtifactsDirectory
{{ Fill ArtifactsDirectory Description }}

```yaml
Type: String
Parameter Sets: Default, Inline
Aliases: ArtifactsPath
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Category
Override document category for this export run.

```yaml
Type: String
Parameter Sets: Default, Inline
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Compose
Optional script block executed to produce additional input objects for composition (inline mode).

Example:

Export-DDSecurityReport -Scope Detailed -ExportFormat Word -ExportPath .\Reports {
Test-DDEmailSpfRecord -DomainName contoso.com
Test-DDDnsBlacklist -NameOrIpAddress 203.0.113.5
}

```yaml
Type: ScriptBlock
Parameter Sets: Inline
Aliases: None
Possible values:

Required: False
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Creator
Override document creator/author for this export run.

```yaml
Type: String
Parameter Sets: Default, Inline
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DisableParallel
{{ Fill DisableParallel Description }}

```yaml
Type: SwitchParameter
Parameter Sets: Default, Inline
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DnsEndpoints
{{ Fill DnsEndpoints Description }}

```yaml
Type: DnsEndpoint[]
Parameter Sets: Default, Inline
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
Parameter Sets: Default, Inline
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DomainOrder
Controls how domains are ordered in the output.

Alphabetical sorts domains A→Z. Input preserves first-seen order from the input
stream/inline composition.

```yaml
Type: String
Parameter Sets: Default, Inline
Aliases: None
Possible values: Alphabetical, Input

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ExcelProfile
Choose the Excel presentation profile.

Workbook exports structured sheets intended for analysis and filtering; Dashboard
emphasizes an at-a-glance overview sheet.

```yaml
Type: String
Parameter Sets: Default, Inline
Aliases: None
Possible values: Workbook, Dashboard

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ExportArtifacts
{{ Fill ExportArtifacts Description }}

```yaml
Type: SwitchParameter
Parameter Sets: Default, Inline
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
Parameter Sets: Default, Inline
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
Parameter Sets: Default, Inline
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -HtmlProfile
Choose the HTML presentation profile.

Document provides a narrative, document-style layout; Dashboard focuses on
high-level, concise summaries suitable for quick review or portals.

```yaml
Type: String
Parameter Sets: Default, Inline
Aliases: None
Possible values: Document, Dashboard

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -InputObject
Objects to compose (SPF/DKIM/DMARC/… view objects). Optional when using -Compose.

Accepts single objects or arrays; enumerables are flattened. If a ScriptBlock is supplied, it is invoked and its output is composed.

```yaml
Type: Object
Parameter Sets: Default, Inline
Aliases: None
Possible values:

Required: False
Position: 0
Default value: None
Accept pipeline input: True (ByValue)
Accept wildcard characters: False
```

### -Keywords
Override document keywords (comma-separated) for this export run.

```yaml
Type: String
Parameter Sets: Default, Inline
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
Parameter Sets: Default, Inline
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
Parameter Sets: Default, Inline
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
Parameter Sets: Default, Inline
Aliases: None
Possible values: FirstSuccess, FastestWins, SequentialFallback, RoundRobin, Random

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
Parameter Sets: Default, Inline
Aliases: OpenReport
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ProviderHelpOptions
Optional overrides for the chosen ProviderHelpPreset. Provide as a hashtable.

Recognized keys: Under (array of section keys such as MX, SPF, DKIM, DMARC, BIMI, ARC),
Topics (array of topic names to order), ShowSummaries, ShowNotes,
ShowBadges, ShowVerified, IncludeRestricted, IncludeThirdParty,
and MaxProviders (integer limit).
Example: @{ Under = 'MX','SPF','DKIM'; ShowNotes = $true; MaxProviders = 10 }.

```yaml
Type: Hashtable
Parameter Sets: Default, Inline
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ProviderHelpPreset
Controls how much provider reference material is embedded beneath each section (MX/SPF/DKIM/DMARC, etc.).

Presets: Off (no provider help), Minimal (only under MX, no summaries/notes),
Standard (balanced defaults), Detailed (enable all summaries/notes/verified/badges under all sections).
Use together with ProviderHelpOptions to fine-tune.

```yaml
Type: String
Parameter Sets: Default, Inline
Aliases: None
Possible values: Off, Minimal, Standard, Detailed

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Scope
Detail scope for section writers.

```yaml
Type: ReportScope
Parameter Sets: Default, Inline
Aliases: None
Possible values: Minimal, Normal, Detailed

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SectionOrder
Explicit section order to use when SectionOrderMode is Custom.

Typical keys include: MX, SPF, DKIM, DMARC, ARC, BIMI, DNSBL, RPKI, NS, SOA, ZoneTransfer,
Wildcard, CAA, Classification, MTA-STS, TLS-RPT, DNSSEC, DANE. Values are normalized (e.g. "TLSRPT" → "TLS-RPT").

```yaml
Type: String[]
Parameter Sets: Default, Inline
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SectionOrderMode
Controls section ordering within each domain.

Canonical uses the built-in order (e.g. MX, SPF, DKIM, DMARC, …), Input orders by
first appearance in your data, and Custom applies the explicit order from SectionOrder.

```yaml
Type: String
Parameter Sets: Default, Inline
Aliases: None
Possible values: Canonical, Input, Custom

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ShowInfoFindings
Include Info-level findings in sections when supported.

```yaml
Type: SwitchParameter
Parameter Sets: Default, Inline
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Subject
Override document subject/description for this export run.

```yaml
Type: String
Parameter Sets: Default, Inline
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SummaryColumnCap
Max status columns in the Word executive summary table.

```yaml
Type: Nullable`1
Parameter Sets: Default, Inline
Aliases: None
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
Parameter Sets: Default, Inline
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Title
Override document title for this export run.

```yaml
Type: String
Parameter Sets: Default, Inline
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

- `System.Object`

## OUTPUTS

- `None`

## RELATED LINKS

- None

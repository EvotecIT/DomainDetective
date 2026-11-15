---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# Set-DDExportOptions
## SYNOPSIS
Sets global export defaults for DomainDetective reports.

## SYNTAX
### __AllParameterSets
```powershell
Set-DDExportOptions [-DefaultFormat <ReportFormat>] [-OutputDirectory <string>] [-ArtifactsDirectory <string>] [-LogoPath <string>] [-HeaderLogoSizePx <Int32>] [-FooterLogoSizePx <Int32>] [-HeaderText <string>] [-FooterText <string>] [-WatermarkText <string>] [-SummaryColumnCap <Int32>] [-CompanyName <string>] [-CompanyAddress <string>] [-CompanyYear <string>] [-Title <string>] [-Subject <string>] [-Category <string>] [-Keywords <string>] [-Creator <string>] [-OpenInBrowser] [-Artifacts] [-NoArtifacts] [-Reset] [-NarrativePlacement <NarrativePlacement>] [<CommonParameters>]
```

## DESCRIPTION
Assessment reports support Title, output paths, opening and artifact settings. Legacy branding,
metadata other than Title, logo sizes and narrative placement overrides are rejected before any defaults change.
SummaryColumnCap accepts only its neutral default of 4. Use Reset to clear retired overrides.

## EXAMPLES

### EXAMPLE 1
```powershell
PS> Set-DDExportOptions -DefaultFormat Pdf -OutputDirectory './Reports'
```

Individual commands can override the default with multiple formats, such as Word,Pdf,Html.

## PARAMETERS

### -Artifacts
Emit artifacts (scan.json, metrics.json, progress.jsonl) by default.

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

### -ArtifactsDirectory
Default artifacts directory (for scan.json, metrics.json, progress.jsonl).

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

### -Category
Assessment exports reject nondefault values for this legacy setting.

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

### -CompanyAddress
Assessment exports reject nondefault values for this legacy setting.

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

### -CompanyName
Assessment exports reject nondefault values for this legacy setting.

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

### -CompanyYear
Assessment exports reject nondefault values for this legacy setting.

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

### -Creator
Assessment exports reject nondefault values for this legacy setting.

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

### -DefaultFormat
Default format for exports, including Pdf. An explicit ExportFormat array on a command overrides this default.

```yaml
Type: ReportFormat
Parameter Sets: __AllParameterSets
Aliases: None
Possible values: Html, Json, Word, Pdf, Excel, Markdown, MarkdownHtml

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -FooterLogoSizePx
Assessment exports reject nondefault values for this legacy setting.

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

### -FooterText
Assessment exports reject nondefault values for this legacy setting.

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

### -HeaderLogoSizePx
Assessment exports reject nondefault values for this legacy setting.

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

### -HeaderText
Assessment exports reject nondefault values for this legacy setting.

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

### -Keywords
Assessment exports reject nondefault values for this legacy setting.

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

### -LogoPath
Assessment exports reject nondefault values for this legacy setting.

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

### -NarrativePlacement
Assessment exports reject nondefault values for this legacy setting.

```yaml
Type: NarrativePlacement
Parameter Sets: __AllParameterSets
Aliases: None
Possible values: Auto, Global, PerDomain, None

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -NoArtifacts
Disable artifact emission by default.

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

### -OpenInBrowser
Open reports after generation (HTML in browser, others via shell).

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

### -OutputDirectory
Default output directory for exported reports.

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

### -Reset
Reset export defaults to built-in values.

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

### -Subject
Assessment exports reject nondefault values for this legacy setting.

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

### -SummaryColumnCap
Assessment exports reject nondefault values for this legacy setting.

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

### -Title
Override the report Title.

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

### -WatermarkText
Assessment exports reject nondefault values for this legacy setting.

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

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

- `None`

## OUTPUTS

- `None`

## RELATED LINKS

- None

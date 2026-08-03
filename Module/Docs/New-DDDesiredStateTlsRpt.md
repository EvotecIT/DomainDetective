---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# New-DDDesiredStateTlsRpt
## SYNOPSIS
Creates a TLS-RPT desired state policy fragment.

## SYNTAX
### __AllParameterSets
```powershell
New-DDDesiredStateTlsRpt [-Enabled <Boolean>] [-RequireRecord <Boolean>] [-RequireSingleRecord <Boolean>] [-RequireRua <Boolean>] [-RequireMailtoRua <Boolean>] [-RequireValidPolicy <Boolean>] [-DisallowRecordOver255 <Boolean>] [-DisallowUnknownTags <Boolean>] [-DisallowInvalidRua <Boolean>] [-DisallowHttpRua <Boolean>] [-AllowedReportDomainSuffixes <string[]>] [<CommonParameters>]
```

## DESCRIPTION
The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.

## EXAMPLES

### EXAMPLE 1
```powershell
PS> New-DDDesiredStateTlsRpt -Enabled $true -RequireRecord $true -RequireValidPolicy $true -AllowedReportDomainSuffixes tlsrpt.vendor.example
```


## PARAMETERS

### -AllowedReportDomainSuffixes
Allowed domain suffixes for TLS-RPT rua endpoints (mailto domains / HTTPS hosts).

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

### -DisallowHttpRua
When true, disallows HTTPS RUA endpoints.

```yaml
Type: Boolean
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DisallowInvalidRua
When true, disallows invalid RUA URIs.

```yaml
Type: Boolean
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DisallowRecordOver255
When true, disallows TLS-RPT records longer than 255 characters.

```yaml
Type: Boolean
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DisallowUnknownTags
When true, disallows unknown/unrecognized TLS-RPT tags.

```yaml
Type: Boolean
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Enabled
Enable/disable the TLS-RPT desired state module.

```yaml
Type: Boolean
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -RequireMailtoRua
When true, require at least one mailto: reporting address.

```yaml
Type: Boolean
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -RequireRecord
When true, require a TLS-RPT record to exist.

```yaml
Type: Boolean
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -RequireRua
When true, require at least one reporting URI (rua=).

```yaml
Type: Boolean
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -RequireSingleRecord
When true, requires exactly one TLS-RPT record to be published.

```yaml
Type: Boolean
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -RequireValidPolicy
When true, require the TLS-RPT record to be syntactically valid.

```yaml
Type: Boolean
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

- `DomainDetective.DesiredState.DesiredStateProfile`

## RELATED LINKS

- None

---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# New-DDDesiredStateDmarc
## SYNOPSIS
Creates a DMARC desired state policy fragment.

## SYNTAX
### __AllParameterSets
```powershell
New-DDDesiredStateDmarc [-Enabled <Boolean>] [-RequireRecord <Boolean>] [-RequireValidRecord <Boolean>] [-RequireSingleRecord <Boolean>] [-AllowedPolicies <string[]>] [-AllowedSubdomainPolicies <string[]>] [-RequireSubdomainPolicyTag <Boolean>] [-AllowedAspfAlignments <string[]>] [-AllowedAdkimAlignments <string[]>] [-RequireRua <Boolean>] [-RequireMailtoRua <Boolean>] [-DisallowHttpRua <Boolean>] [-DisallowRuf <Boolean>] [-DisallowHttpRuf <Boolean>] [-DisallowWeakPolicy <Boolean>] [-DisallowRecordOver255 <Boolean>] [-DisallowUnknownTags <Boolean>] [-DisallowDeprecatedTags <Boolean>] [-AllowedReportDomainSuffixes <string[]>] [-RequireExternalReportAuthorization <Boolean>] [<CommonParameters>]
```

## DESCRIPTION
The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.

## EXAMPLES

### EXAMPLE 1
```powershell
PS> New-DDDesiredStateDmarc -Enabled $true -AllowedPolicies reject,quarantine -RequireRua $true -AllowedReportDomainSuffixes dmarc.powermarc.com
```


## PARAMETERS

### -AllowedAdkimAlignments
Allowed adkim alignment values (r/s).

```yaml
Type: String[]
Parameter Sets: __AllParameterSets
Aliases: None
Possible values: r, s

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -AllowedAspfAlignments
Allowed aspf alignment values (r/s).

```yaml
Type: String[]
Parameter Sets: __AllParameterSets
Aliases: None
Possible values: r, s

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -AllowedPolicies
Allowed DMARC policy values (p=).

```yaml
Type: String[]
Parameter Sets: __AllParameterSets
Aliases: None
Possible values: none, quarantine, reject

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -AllowedReportDomainSuffixes
Allowed domain suffixes for DMARC rua/ruf URIs.

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

### -AllowedSubdomainPolicies
Allowed DMARC subdomain policy values (sp=).

```yaml
Type: String[]
Parameter Sets: __AllParameterSets
Aliases: None
Possible values: none, quarantine, reject

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DisallowDeprecatedTags
When true, disallows deprecated DMARC tags (e.g., pct=, rf=).

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

### -DisallowHttpRua
When true, disallows HTTPS endpoints in rua=.

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

### -DisallowHttpRuf
When true, disallows HTTPS endpoints in ruf=.

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
When true, disallows DMARC records longer than 255 characters.

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

### -DisallowRuf
When true, disallows DMARC forensic reporting (ruf=).

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
When true, disallows unknown/unrecognized DMARC tags.

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

### -DisallowWeakPolicy
When true, disallows weak policy (p=none or sp=none).

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
Enable/disable the DMARC desired state module.

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

### -RequireExternalReportAuthorization
When true, requires external reporting domains to be authorized via _report._dmarc.

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
When true, requires at least one mailto: rua address.

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
When true, require a DMARC record to exist.

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
When true, require at least one aggregate reporting URI (rua=).

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
When true, requires exactly one DMARC record to be published.

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

### -RequireSubdomainPolicyTag
When true, requires an explicit sp= tag to be present.

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

### -RequireValidRecord
When true, requires the DMARC record to be syntactically valid.

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

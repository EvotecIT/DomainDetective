---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# New-DDDesiredStateSpf
## SYNOPSIS
Creates an SPF desired state policy fragment.

## SYNTAX
### __AllParameterSets
```powershell
New-DDDesiredStateSpf [-Enabled <bool>] [-RequireRecord <bool>] [-RequireValidRecord <bool>] [-RequireSingleRecord <bool>] [-RequireEffectiveSpfSends <bool>] [-AllowedAllMechanisms <string[]>] [-RequireAllMechanism <bool>] [-MaxDnsLookups <int>] [-RequireDenyAll <bool>] [-RequiredIncludeDomains <string[]>] [-MatchResolvedIncludes <bool>] [-DisallowPtr <bool>] [-DisallowUnknownMechanisms <bool>] [-DisallowRedirect <bool>] [-RequireRedirect <bool>] [-DisallowExp <bool>] [-DisallowPermError <bool>] [-DisallowCname <bool>] [-AllowedRedirectDomainSuffixes <string[]>] [<CommonParameters>]
```

## DESCRIPTION
The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.

## EXAMPLES

### EXAMPLE 1
```powershell
PS> New-DDDesiredStateSpf -Enabled $true -RequireRecord $true -AllowedAllMechanisms '-all' -MaxDnsLookups 10 -DisallowPtr $true
```


## PARAMETERS

### -AllowedAllMechanisms
Allowed all mechanisms (e.g., -all, ~all).

```yaml
Type: String[]
Parameter Sets: __AllParameterSets
Aliases: None
Possible values: -all, ~all, ?all, +all

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -AllowedRedirectDomainSuffixes
Allowed domain suffixes for redirect= target.

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

### -DisallowCname
When true, disallows SPF records resolved through a CNAME alias.

```yaml
Type: Nullable`1
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DisallowExp
When true, disallows exp= (explanation) modifier.

```yaml
Type: Nullable`1
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DisallowPermError
When true, disallows SPF PermError results.

```yaml
Type: Nullable`1
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DisallowPtr
When true, disallows the SPF ptr mechanism.

```yaml
Type: Nullable`1
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DisallowRedirect
When true, disallows the redirect= modifier.

```yaml
Type: Nullable`1
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DisallowUnknownMechanisms
When true, disallows unknown mechanisms/modifiers.

```yaml
Type: Nullable`1
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
Enable/disable the SPF desired state module.

```yaml
Type: Nullable`1
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -MatchResolvedIncludes
When true, checks required include domains against the resolved include chain.

```yaml
Type: Nullable`1
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -MaxDnsLookups
Maximum allowed SPF DNS lookups.

```yaml
Type: Nullable`1
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -RequireAllMechanism
When true, requires the SPF record to include an all mechanism (e.g., -all, ~all).

```yaml
Type: Nullable`1
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -RequireDenyAll
When true, requires the policy to deny all sending (v=spf1 -all).

```yaml
Type: Nullable`1
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -RequiredIncludeDomains
Include domains that must be present in the SPF record.

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

### -RequireEffectiveSpfSends
When true, requires SPF to effectively authorize outbound senders after resolving include/redirect chains.

```yaml
Type: Nullable`1
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
When true, require an SPF record to exist.

```yaml
Type: Nullable`1
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -RequireRedirect
When true, requires the redirect= modifier to be present.

```yaml
Type: Nullable`1
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
When true, requires exactly one SPF record to be published.

```yaml
Type: Nullable`1
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
When true, requires the SPF record to be syntactically valid.

```yaml
Type: Nullable`1
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

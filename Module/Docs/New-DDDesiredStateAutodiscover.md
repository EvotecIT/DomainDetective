---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# New-DDDesiredStateAutodiscover
## SYNOPSIS
Creates an Autodiscover desired state policy fragment.

## SYNTAX
### __AllParameterSets
```powershell
New-DDDesiredStateAutodiscover [-Enabled <bool>] [-RequireSrvRecord <bool>] [-RequireAutodiscoverCname <bool>] [-RequireAutoconfigCname <bool>] [-AllowedSrvTargetSuffixes <string[]>] [-AllowedAutodiscoverCnameTargetSuffixes <string[]>] [-AllowedAutoconfigCnameTargetSuffixes <string[]>] [-RequireAnyValidEndpoint <bool>] [-AllowedValidEndpointHostSuffixes <string[]>] [<CommonParameters>]
```

## DESCRIPTION
The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.

## EXAMPLES

### EXAMPLE 1
```powershell
PS> New-DDDesiredStateAutodiscover -RequireAutodiscoverCname $true -AllowedAutodiscoverCnameTargetSuffixes outlook.com -RequireAnyValidEndpoint $true
```


## PARAMETERS

### -AllowedAutoconfigCnameTargetSuffixes
Allowed suffixes for autoconfig.<domain> CNAME target.

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

### -AllowedAutodiscoverCnameTargetSuffixes
Allowed suffixes for autodiscover.<domain> CNAME target.

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

### -AllowedSrvTargetSuffixes
Allowed suffixes for _autodiscover._tcp SRV target.

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

### -AllowedValidEndpointHostSuffixes
Allowed suffixes for hosts of valid Autodiscover endpoints.

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

### -Enabled
Enable/disable the Autodiscover desired state module.

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

### -RequireAnyValidEndpoint
When true, requires at least one Autodiscover endpoint to return valid XML or JSON.

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

### -RequireAutoconfigCname
When true, require an autoconfig.<domain> CNAME record to exist.

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

### -RequireAutodiscoverCname
When true, require an autodiscover.<domain> CNAME record to exist.

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

### -RequireSrvRecord
When true, require an _autodiscover._tcp SRV record to exist.

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

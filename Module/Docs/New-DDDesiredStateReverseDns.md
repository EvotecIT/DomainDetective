---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# New-DDDesiredStateReverseDns
## SYNOPSIS
Creates a reverse DNS desired state policy fragment.

## SYNTAX
### __AllParameterSets
```powershell
New-DDDesiredStateReverseDns [-Enabled <bool>] [-RequireAtLeastOneResult <bool>] [-RequirePtrPresent <bool>] [-RequirePtrMatchesExpectedHost <bool>] [-AllowedPtrSuffixes <string[]>] [-RequireForwardConfirmed <bool>] [<CommonParameters>]
```

## DESCRIPTION
The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.

## EXAMPLES

### EXAMPLE 1
```powershell
PS> New-DDDesiredStateReverseDns -RequirePtrPresent $true -RequireForwardConfirmed $true
```


## PARAMETERS

### -AllowedPtrSuffixes
Allowed PTR hostname suffixes (e.g., mail.protection.outlook.com).

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
Enable/disable the reverse DNS desired state module.

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

### -RequireAtLeastOneResult
When true, warns if no reverse DNS results were analyzed.

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

### -RequireForwardConfirmed
When true, requires forward-confirmed reverse DNS (FCrDNS) for each IP.

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

### -RequirePtrMatchesExpectedHost
When true, requires at least one PTR record to match the expected host name.

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

### -RequirePtrPresent
When true, requires each analyzed IP address to have at least one PTR record.

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

---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# New-DDDesiredStateCertificateInventory
## SYNOPSIS
Creates a certificate inventory desired state policy fragment.

## SYNTAX
### __AllParameterSets
```powershell
New-DDDesiredStateCertificateInventory [-Enabled <bool>] [-BaselineProfile <string>] [-IncludeCompliant <bool>] [-MaxEndpoints <int>] [-PolicyOverridesPath <string>] [<CommonParameters>]
```

## DESCRIPTION
The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.

## EXAMPLES

### EXAMPLE 1
```powershell
New-DDDesiredStateCertificateInventory -PolicyOverridesPath 'C:\Path'
```


## PARAMETERS

### -BaselineProfile
Baseline policy profile (Strict, Balanced, Legacy).

```yaml
Type: String
Parameter Sets: __AllParameterSets
Aliases: None
Possible values: Strict, Balanced, Legacy

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Enabled
Enable/disable certificate inventory desired state evaluation.

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

### -IncludeCompliant
Include endpoints with no policy violations.

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

### -MaxEndpoints
Maximum endpoint rows returned by policy evaluation.

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

### -PolicyOverridesPath
Optional JSON file path with certificate inventory policy overrides.

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

- `DomainDetective.DesiredState.DesiredStateProfile`

## RELATED LINKS

- None

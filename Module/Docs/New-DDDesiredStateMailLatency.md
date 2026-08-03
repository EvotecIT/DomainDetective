---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# New-DDDesiredStateMailLatency
## SYNOPSIS
Creates a mail latency desired state policy fragment.

## SYNTAX
### __AllParameterSets
```powershell
New-DDDesiredStateMailLatency [-Enabled <Boolean>] [-RequireAtLeastOneResult <Boolean>] [-RequireAllConnectSuccess <Boolean>] [-RequireAllBannerSuccess <Boolean>] [-MaxConnectTimeMs <Int32>] [-MaxBannerTimeMs <Int32>] [<CommonParameters>]
```

## DESCRIPTION
The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.

## EXAMPLES

### EXAMPLE 1
```powershell
PS> New-DDDesiredStateMailLatency -Enabled $true -RequireAllConnectSuccess $true -MaxConnectTimeMs 2000 -MaxBannerTimeMs 2000
```


## PARAMETERS

### -Enabled
Enable/disable the mail latency desired state module.

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

### -MaxBannerTimeMs
Maximum allowed banner read time in milliseconds.

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

### -MaxConnectTimeMs
Maximum allowed connect time in milliseconds.

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

### -RequireAllBannerSuccess
When true, require all servers to successfully return an SMTP banner.

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

### -RequireAllConnectSuccess
When true, require all servers to successfully connect.

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

### -RequireAtLeastOneResult
When true, require at least one latency result to be present.

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

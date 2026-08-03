---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# Get-DDCertificateInventoryReuse
## SYNOPSIS
Builds certificate reuse and endpoint assignment mapping from persisted inventory snapshots.

## SYNTAX
### __AllParameterSets
```powershell
Get-DDCertificateInventoryReuse [-CacheDirectory <string>] [-SinceUtc <DateTime>] [-IncludeSingletons] [-MinEndpoints <int>] [-MaxCertificates <int>] [-MaxEndpointsPerCertificate <int>] [<CommonParameters>]
```

## DESCRIPTION
Groups latest endpoint observations by certificate identity to show where each certificate is assigned and whether it spans multiple services.

## EXAMPLES

### EXAMPLE 1
```powershell
Get-DDCertificateInventoryReuse -SinceUtc (Get-Date).ToUniversalTime().AddDays(-30)
```


### EXAMPLE 2
```powershell
Get-DDCertificateInventoryReuse -IncludeSingletons -MinEndpoints 1
```


## PARAMETERS

### -CacheDirectory
Certificate monitor cache directory containing the inventory folder.

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

### -IncludeSingletons
Include certificates assigned to only one endpoint.

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

### -MaxCertificates
Maximum certificate rows returned.

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

### -MaxEndpointsPerCertificate
Maximum endpoint references returned per certificate row.

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

### -MinEndpoints
Minimum endpoint count required per certificate row.

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

### -SinceUtc
Only include snapshots captured since this UTC date/time.

```yaml
Type: DateTime
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

- `DomainDetective.CertificateInventoryReuseSummary`

## RELATED LINKS

- None

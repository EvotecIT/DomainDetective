---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# Get-DDCertificateInventorySummary
## SYNOPSIS
Builds a certificate inventory summary from persisted monitor snapshots.

## SYNTAX
### __AllParameterSets
```powershell
Get-DDCertificateInventorySummary [-CacheDirectory <string>] [-SinceUtc <DateTime>] [-ExpiringWithinDays <int>] [-MaxExpiringEndpoints <int>] [<CommonParameters>]
```

## DESCRIPTION
Loads stored certificate inventory snapshots and returns aggregate metrics including issuer/service distribution and expiring endpoints.

## EXAMPLES

### EXAMPLE 1
```powershell
Get-DDCertificateInventorySummary -SinceUtc (Get-Date).ToUniversalTime().AddDays(-30)
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

### -ExpiringWithinDays
Expiring-soon window in days.

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

### -MaxExpiringEndpoints
Maximum number of expiring endpoints returned in summary details.

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

- `DomainDetective.CertificateInventorySummary`

## RELATED LINKS

- None

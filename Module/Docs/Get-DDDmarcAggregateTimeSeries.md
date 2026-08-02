---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# Get-DDDmarcAggregateTimeSeries
## SYNOPSIS
Builds a DMARC Aggregate (RUA) time-series view from stored snapshots.

## SYNTAX
### __AllParameterSets
```powershell
Get-DDDmarcAggregateTimeSeries [-DomainName] <string[]> -StorePath <string> [-SinceUtc <datetime>] [-Days <int>] [<CommonParameters>]
```

## DESCRIPTION
Loads normalized snapshots from disk and outputs a view object suitable for Export-DDSecurityReport.

## EXAMPLES

### EXAMPLE 1
```powershell
Get-DDDmarcAggregateTimeSeries -DomainName example.com -StorePath .\Store
```


## PARAMETERS

### -Days
Convenience override for -SinceUtc (UTC): include snapshots from the last N days.

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

### -DomainName
Domain(s) to load.

```yaml
Type: String[]
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: True
Position: 0
Default value: None
Accept pipeline input: True (ByValue, ByPropertyName)
Accept wildcard characters: False
```

### -SinceUtc
Only include snapshots with end time on/after this UTC date/time.

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

### -StorePath
Root directory for snapshot storage.

```yaml
Type: String
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: True
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

- `System.String[]`

## OUTPUTS

- `DomainDetective.Views.DmarcAggregateTimeSeriesInfo`

## RELATED LINKS

- None

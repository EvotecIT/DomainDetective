---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# Get-DDCertificateInventoryDiff
## SYNOPSIS
Compares two persisted certificate inventory snapshots and returns endpoint deltas.

## SYNTAX
### __AllParameterSets
```powershell
Get-DDCertificateInventoryDiff [-CacheDirectory <string>] [-SinceUtc <datetime>] [-PreviousUtc <datetime>] [-CurrentUtc <datetime>] [-IncludeUnchanged] [-MaxEndpoints <int>] [<CommonParameters>]
```

## DESCRIPTION
When snapshot timestamps are not specified, the cmdlet compares the latest snapshot with the one before it.

## EXAMPLES

### EXAMPLE 1
```powershell
Get-DDCertificateInventoryDiff
```


### EXAMPLE 2
```powershell
Get-DDCertificateInventoryDiff -PreviousUtc (Get-Date).ToUniversalTime().AddDays(-7) -CurrentUtc (Get-Date).ToUniversalTime() -IncludeUnchanged
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

### -CurrentUtc
Timestamp selector for the current snapshot.

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

### -IncludeUnchanged
Include unchanged endpoints in result rows.

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

### -MaxEndpoints
Maximum endpoint rows returned.

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

### -PreviousUtc
Timestamp selector for the previous snapshot.

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

### -SinceUtc
Only include snapshots captured since this UTC date/time.

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

- `DomainDetective.CertificateInventoryDiffSummary`

## RELATED LINKS

- None

---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# Get-DDCertificateInventoryCtHealth
## SYNOPSIS
Builds CT diagnostics health timeline from persisted certificate inventory snapshots.

## SYNTAX
### __AllParameterSets
```powershell
Get-DDCertificateInventoryCtHealth [-CacheDirectory <string>] [-SinceUtc <datetime>] [-UntilUtc <datetime>] [-LatestOnly] [-MaxSnapshots <int>] [-MaxFailed <int>] [-MaxCircuitOpen <int>] [-MaxLagAfter <long>] [-FailOnAnyBreach] [-FailOnThresholdBreach] [<CommonParameters>]
```

## DESCRIPTION
Returns per-snapshot CT status with threshold evaluation and last breach metadata so monitoring/reporting layers can render status panels and trends.

## EXAMPLES

### EXAMPLE 1
```powershell
Get-DDCertificateInventoryCtHealth -SinceUtc (Get-Date).ToUniversalTime().AddDays(-30) -MaxSnapshots 60
```


### EXAMPLE 2
```powershell
Get-DDCertificateInventoryCtHealth -LatestOnly -MaxFailed 0 -MaxCircuitOpen 0 -MaxLagAfter 5000 -FailOnThresholdBreach
```


### EXAMPLE 3
```powershell
Get-DDCertificateInventoryCtHealth -SinceUtc (Get-Date).ToUniversalTime().AddDays(-7) -FailOnAnyBreach -MaxFailed 0 -FailOnThresholdBreach
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

### -FailOnAnyBreach
When set, fail if any returned snapshot breaches thresholds (otherwise latest snapshot only).

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

### -FailOnThresholdBreach
When set, throw a terminating error when threshold breach condition is met.

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

### -LatestOnly
Only evaluate the latest snapshot after date filtering.

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

### -MaxCircuitOpen
Alert threshold: maximum allowed diagnostics in CircuitOpen state.

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

### -MaxFailed
Alert threshold: maximum allowed diagnostics in Failed state.

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

### -MaxLagAfter
Alert threshold: maximum allowed LagAfter value across diagnostics.

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

### -MaxSnapshots
Maximum timeline rows returned.

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

### -UntilUtc
Only include snapshots captured up to this UTC date/time.

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

- `DomainDetective.CertificateInventoryNativeCtDiagnosticsHealthSummary`

## RELATED LINKS

- None

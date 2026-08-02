---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# Get-DDCertificateInventoryCtDiagnostics
## SYNOPSIS
Queries persisted native CT ingestion diagnostics captured with certificate inventory snapshots.

## SYNTAX
### __AllParameterSets
```powershell
Get-DDCertificateInventoryCtDiagnostics [-CacheDirectory <string>] [-SinceUtc <datetime>] [-UntilUtc <datetime>] [-LatestOnly] [-State <string[]>] [-LogUrlContains <string>] [-ScopeContains <string>] [-CircuitOpenOnly] [-FailureOnly] [-LagBeforeMin <long>] [-LagBeforeMax <long>] [-LagAfterMin <long>] [-LagAfterMax <long>] [-MaxResults <int>] [-MaxFailed <int>] [-MaxCircuitOpen <int>] [-MaxLagAfter <long>] [-FailOnThresholdBreach] [<CommonParameters>]
```

## DESCRIPTION
Use this cmdlet to inspect CT ingestion health over time (for example failed logs, open circuits, or high lag after processing).

## EXAMPLES

### EXAMPLE 1
```powershell
Get-DDCertificateInventoryCtDiagnostics -SinceUtc (Get-Date).ToUniversalTime().AddDays(-7) -State Failed
```


### EXAMPLE 2
```powershell
Get-DDCertificateInventoryCtDiagnostics -State CircuitOpen -LagAfterMin 10000
```


### EXAMPLE 3
```powershell
Get-DDCertificateInventoryCtDiagnostics -LatestOnly -MaxFailed 0 -MaxCircuitOpen 0 -MaxLagAfter 5000 -FailOnThresholdBreach
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

### -CircuitOpenOnly
Only return diagnostics currently marked as circuit open.

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
When set, the cmdlet throws a terminating error if any configured threshold is breached.

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

### -FailureOnly
Only return diagnostics that include failure messages.

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

### -LagAfterMax
Optional maximum LagAfter value.

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

### -LagAfterMin
Optional minimum LagAfter value.

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

### -LagBeforeMax
Optional maximum LagBefore value.

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

### -LagBeforeMin
Optional minimum LagBefore value.

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

### -LogUrlContains
Optional contains filter applied to CT log URL.

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
Alert threshold: maximum allowed LagAfter value across matched diagnostics.

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

### -MaxResults
Maximum number of entries returned.

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

### -ScopeContains
Optional contains filter applied to diagnostic scope.

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

### -State
Optional state filter(s): Succeeded, Failed, CircuitOpen, Unknown.

```yaml
Type: String[]
Parameter Sets: __AllParameterSets
Aliases: None
Possible values: Succeeded, Failed, CircuitOpen, Unknown

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

- `DomainDetective.CertificateInventoryNativeCtDiagnosticsResult`

## RELATED LINKS

- None

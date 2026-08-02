---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# Get-DDCertificateInventoryPolicyDrift
## SYNOPSIS
Builds endpoint-level certificate policy drift between two persisted inventory snapshots.

## SYNTAX
### __AllParameterSets
```powershell
Get-DDCertificateInventoryPolicyDrift [-CacheDirectory <string>] [-SinceUtc <datetime>] [-PreviousUtc <datetime>] [-CurrentUtc <datetime>] [-BaselineProfile <string>] [-ChangedOnly] [-MaxEndpoints <int>] [-PolicyOverridesPath <string>] [<CommonParameters>]
```

## DESCRIPTION
Compares baseline-policy compliance between snapshots and reports added/resolved violation codes per endpoint.

## EXAMPLES

### EXAMPLE 1
```powershell
Get-DDCertificateInventoryPolicyDrift -ChangedOnly
```


### EXAMPLE 2
```powershell
Get-DDCertificateInventoryPolicyDrift -BaselineProfile Strict -PreviousUtc (Get-Date).ToUniversalTime().AddDays(-7) -CurrentUtc (Get-Date).ToUniversalTime()
```


### EXAMPLE 3
```powershell
Get-DDCertificateInventoryPolicyDrift -PolicyOverridesPath .\policy-overrides.json -ChangedOnly
```


## PARAMETERS

### -BaselineProfile
Policy baseline profile to evaluate (Strict, Balanced, Legacy).

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

### -ChangedOnly
Only return endpoint rows with detected policy drift.

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

### -CurrentUtc
Optional current snapshot selector (latest snapshot at or before this UTC time).

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

### -PolicyOverridesPath
Optional JSON file path with policy override rules.

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

### -PreviousUtc
Optional previous snapshot selector (latest snapshot at or before this UTC time).

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

- `DomainDetective.CertificateInventoryPolicyDriftSummary`

## RELATED LINKS

- None

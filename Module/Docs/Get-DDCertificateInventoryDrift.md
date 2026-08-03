---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# Get-DDCertificateInventoryDrift
## SYNOPSIS
Builds endpoint-level certificate drift from persisted inventory snapshots.

## SYNTAX
### __AllParameterSets
```powershell
Get-DDCertificateInventoryDrift [-CacheDirectory <string>] [-SinceUtc <DateTime>] [-ChangedOnly] [-MaxEndpoints <int>] [-MinimumSeverity <string>] [-ChangeKind <string[]>] [-ChangeKindMatch <string>] [<CommonParameters>]
```

## DESCRIPTION
Detects certificate rotation and issuer/expiry/service/auth-profile/chain-source drift between observations for each endpoint, including severity and change-kind classification with optional minimum-severity filtering.

## EXAMPLES

### EXAMPLE 1
```powershell
Get-DDCertificateInventoryDrift -SinceUtc (Get-Date).ToUniversalTime().AddDays(-14) -ChangedOnly
```


### EXAMPLE 2
```powershell
Get-DDCertificateInventoryDrift -MinimumSeverity Medium
```


### EXAMPLE 3
```powershell
Get-DDCertificateInventoryDrift -ChangeKind Certificate,AuthProfile
```


### EXAMPLE 4
```powershell
Get-DDCertificateInventoryDrift -ChangeKind Certificate,Issuer -ChangeKindMatch All
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

### -ChangedOnly
Only return endpoints where drift was observed.

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

### -ChangeKind
Optional list of required drift change kinds.

```yaml
Type: String[]
Parameter Sets: __AllParameterSets
Aliases: None
Possible values: Certificate, Issuer, Expiry, Service, AuthProfile, ChainSource

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ChangeKindMatch
Change-kind matching mode: Any returns rows matching any selected kind; All requires all selected kinds.

```yaml
Type: String
Parameter Sets: __AllParameterSets
Aliases: None
Possible values: Any, All

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

### -MinimumSeverity
Optional minimum drift severity filter (None is equivalent to omitting this parameter).

```yaml
Type: String
Parameter Sets: __AllParameterSets
Aliases: None
Possible values: None, Low, Medium, High

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

- `DomainDetective.CertificateInventoryDriftSummary`

## RELATED LINKS

- None

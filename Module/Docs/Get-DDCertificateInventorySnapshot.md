---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# Get-DDCertificateInventorySnapshot
## SYNOPSIS
Reads persisted certificate inventory snapshots from local storage.

## SYNTAX
### __AllParameterSets
```powershell
Get-DDCertificateInventorySnapshot [-CacheDirectory <string>] [-SinceUtc <datetime>] [-UntilUtc <datetime>] [-MaxSnapshots <int>] [-Latest] [-WithoutEntries] [<CommonParameters>]
```

## DESCRIPTION
Returns raw snapshot objects so you can inspect or post-process captured endpoint certificate data directly.

## EXAMPLES

### EXAMPLE 1
```powershell
Get-DDCertificateInventorySnapshot -Latest
```


### EXAMPLE 2
```powershell
Get-DDCertificateInventorySnapshot -SinceUtc (Get-Date).ToUniversalTime().AddDays(-7) -WithoutEntries
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

### -Latest
Return only the latest snapshot after applying filters.

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

### -MaxSnapshots
Maximum number of snapshots returned (latest N). Use 0 for unlimited.

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

### -WithoutEntries
When set, strips endpoint entries and returns snapshot metadata only.

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

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

- `None`

## OUTPUTS

- `DomainDetective.CertificateInventorySnapshot`

## RELATED LINKS

- None

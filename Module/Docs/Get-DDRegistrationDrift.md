---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# Get-DDRegistrationDrift
## SYNOPSIS
Builds a structured WHOIS/RDAP drift view from stored registration snapshots.

## SYNTAX
### __AllParameterSets
```powershell
Get-DDRegistrationDrift [-DomainName] <string> -StorePath <string> [-SinceUtc <datetime>] [<CommonParameters>]
```

## DESCRIPTION
Loads stored snapshots for a domain and produces a drift view suitable for Word/HTML composition reports.

## EXAMPLES

### EXAMPLE 1
```powershell
Get-DDRegistrationDrift -DomainName example.com -StorePath .\Store -SinceUtc (Get-Date).ToUniversalTime().AddDays(-90)
```


## PARAMETERS

### -DomainName
Domain to load snapshots for.

```yaml
Type: String
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
Only load snapshots captured since this UTC date/time.

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

- `System.String`

## OUTPUTS

- `DomainDetective.Views.RegistrationDriftInfo`

## RELATED LINKS

- None

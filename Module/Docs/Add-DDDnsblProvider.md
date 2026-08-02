---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# Add-DDDnsblProvider
## SYNOPSIS
Adds a DNSBL provider entry to an analysis object.

## SYNTAX
### __AllParameterSets
```powershell
Add-DDDnsblProvider [-Domain] <string> [-Enabled <bool>] [-Comment <string>] [-InputObject <DNSBLAnalysis>] [<CommonParameters>]
```

## DESCRIPTION
Part of the DomainDetective project.

## EXAMPLES

### EXAMPLE 1
```powershell
Add-DDDnsblProvider -Domain "dnsbl.example.com"
```


## PARAMETERS

### -Comment
Optional descriptive comment.

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

### -Domain
Domain name of the DNSBL provider.

```yaml
Type: String
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Enabled
Sets the provider as enabled.

```yaml
Type: Boolean
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -InputObject
Analysis object to add the provider to.

```yaml
Type: DNSBLAnalysis
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: True (ByValue)
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

- `DomainDetective.DNSBLAnalysis`

## OUTPUTS

- `None`

## RELATED LINKS

- None

---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# Remove-DDDnsblProvider
## SYNOPSIS
Removes a DNSBL provider entry from an analysis object.

## SYNTAX
### __AllParameterSets
```powershell
Remove-DDDnsblProvider [-Domain] <string> [-InputObject <DNSBLAnalysis>] [<CommonParameters>]
```

## DESCRIPTION
Part of the DomainDetective project.

## EXAMPLES

### EXAMPLE 1
```powershell
Remove-DDDnsblProvider -Domain dnsbl.example.com
```


## PARAMETERS

### -Domain
Domain name of the provider to remove.

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

### -InputObject
Analysis object to modify.

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

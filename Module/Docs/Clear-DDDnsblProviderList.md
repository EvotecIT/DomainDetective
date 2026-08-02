---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# Clear-DDDnsblProviderList
## SYNOPSIS
Removes all DNSBL providers from an analysis object.

## SYNTAX
### __AllParameterSets
```powershell
Clear-DDDnsblProviderList [-InputObject <DNSBLAnalysis>] [<CommonParameters>]
```

## DESCRIPTION
Part of the DomainDetective project.

## EXAMPLES

### EXAMPLE 1
```powershell
Clear-DDDnsblProviderList
```


## PARAMETERS

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

---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# Import-DDEmailTlsRpt
## SYNOPSIS
Imports TLSRPT JSON reports.

## SYNTAX
### __AllParameterSets
```powershell
Import-DDEmailTlsRpt [-Path] <string> [-MaxUncompressedMb <int>] [<CommonParameters>]
```

## DESCRIPTION
Part of the DomainDetective project.

## EXAMPLES

### EXAMPLE 1
```powershell
Import-DDEmailTlsRpt -Path ./report.json
```


## PARAMETERS

### -MaxUncompressedMb
Maximum expanded report size in MiB. The default is 50; 0 means unlimited.

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

### -Path
Path to the JSON report.

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

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

- `System.String`

## OUTPUTS

- `DomainDetective.TlsRptSummary`

## RELATED LINKS

- None

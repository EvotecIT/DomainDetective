---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# New-DDDesiredStateAssessmentPolicy
## SYNOPSIS
Creates an assessment policy desired state fragment.

## SYNTAX
### __AllParameterSets
```powershell
New-DDDesiredStateAssessmentPolicy [-SuppressCodes <string[]>] [-SeverityOverrides <hashtable>] [<CommonParameters>]
```

## DESCRIPTION
This policy can suppress or re-severity built-in assessment codes to match organization intent.

## EXAMPLES

### EXAMPLE 1
```powershell
PS> New-DDDesiredStateAssessmentPolicy -SuppressCodes DMARC.Alignment.Mismatch -SeverityOverrides @{ 'DNSSEC.ChainInvalid' = 'Info' }
```


## PARAMETERS

### -SeverityOverrides
Assessment severity overrides as a hashtable: @{ 'CODE' = 'Warning' }.

```yaml
Type: Hashtable
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SuppressCodes
Assessment codes to suppress.

```yaml
Type: String[]
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

- `DomainDetective.DesiredState.DesiredStateProfile`

## RELATED LINKS

- None

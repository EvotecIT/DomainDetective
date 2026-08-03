---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# Get-DDTlsCertificateInfo
## SYNOPSIS
Returns details about a certificate file.

## SYNTAX
### __AllParameterSets
```powershell
Get-DDTlsCertificateInfo [-Path] <string> [-ShowChain] [-SkipRevocation] [<CommonParameters>]
```

## DESCRIPTION
Part of the DomainDetective project.

## EXAMPLES

### EXAMPLE 1
```powershell
Get-DDTlsCertificateInfo -Path ./cert.pem
```


## PARAMETERS

### -Path
Path to a PEM or DER encoded certificate.

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

### -ShowChain
Include certificate chain in the output.

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

### -SkipRevocation
Do not check certificate revocation status.

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

- `None`

## RELATED LINKS

- None

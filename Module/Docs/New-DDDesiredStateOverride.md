---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# New-DDDesiredStateOverride
## SYNOPSIS
Creates a desired state override (domain and/or classification specific).

## SYNTAX
### __AllParameterSets
```powershell
New-DDDesiredStateOverride [[-ScriptBlock] <scriptblock>] [-DomainPatterns <string[]>] [-Classifications <MailDomainClassificationCategory[]>] [-Profile <DesiredStateProfile>] [<CommonParameters>]
```

## DESCRIPTION
The returned object is intended to be used with New-DDDesiredState or added to an existing configuration.

## EXAMPLES

### EXAMPLE 1
```powershell
PS> New-DDDesiredStateOverride -DomainPatterns '*.example.com' -Classifications Parked { New-DDDesiredStateSpf -RequireDenyAll $true; New-DDDesiredStateDmarc -RequireRua $false }
```


## PARAMETERS

### -Classifications
Mail domain classifications to match (e.g., Sending, Receiving, Parked).

```yaml
Type: MailDomainClassificationCategory[]
Parameter Sets: __AllParameterSets
Aliases: None
Possible values: SendingAndReceiving, ReceivingOnly, SendingOnly, Parked, Unknown

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DomainPatterns
Wildcard domain patterns to match (e.g., *.example.com).

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

### -Profile
Optional explicit profile fragment to apply to the override.

```yaml
Type: DesiredStateProfile
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ScriptBlock
Optional script block that returns desired state profile fragments to be applied to the override.

```yaml
Type: ScriptBlock
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

- `None`

## OUTPUTS

- `DomainDetective.DesiredState.DesiredStateOverride`

## RELATED LINKS

- None

---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# Set-DDPersona
## SYNOPSIS
Enables, configures, or disables narration personas.

## SYNTAX
### View (Default)
```powershell
Set-DDPersona [<CommonParameters>]
```

### Set
```powershell
Set-DDPersona -Persona <PersonaKind> [-Live] [-NarrateVerbose] [<CommonParameters>]
```

### Off
```powershell
Set-DDPersona -Off [<CommonParameters>]
```

## DESCRIPTION
Enables, configures, or disables narration personas.

## EXAMPLES

### EXAMPLE 1
```powershell
Set-DDPersona -Live
```


### EXAMPLE 2
```powershell
Set-DDPersona -Off
```


### EXAMPLE 3
```powershell
Set-DDPersona -Persona 'Value'
```


## PARAMETERS

### -Live
Enable live narration.

```yaml
Type: SwitchParameter
Parameter Sets: Set
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -NarrateVerbose
Include verbose narration.

```yaml
Type: SwitchParameter
Parameter Sets: Set
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Off
Disable persona narration.

```yaml
Type: SwitchParameter
Parameter Sets: Off
Aliases: None
Possible values:

Required: True
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Persona
Persona style to use.

```yaml
Type: PersonaKind
Parameter Sets: Set
Aliases: None
Possible values: Business, Funny, Geek, Noir, Pirate

Required: True
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

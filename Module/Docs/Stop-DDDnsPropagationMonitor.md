---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# Stop-DDDnsPropagationMonitor
## SYNOPSIS
Stops a running DNS propagation monitor.

## SYNTAX
### __AllParameterSets
```powershell
Stop-DDDnsPropagationMonitor [-Monitor] <DnsPropagationMonitor> [<CommonParameters>]
```

## DESCRIPTION
Part of the DomainDetective project.

## EXAMPLES

### EXAMPLE 1
```powershell
Stop-DDDnsPropagationMonitor -Monitor $monitor
```


## PARAMETERS

### -Monitor
Monitor instance returned by Start-DnsPropagationMonitor.

```yaml
Type: DnsPropagationMonitor
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: True
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

- `None`

## RELATED LINKS

- None

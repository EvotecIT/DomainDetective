---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# New-DDDesiredState
## SYNOPSIS
Creates a desired state configuration object for use with DomainDetective.

## SYNTAX
### __AllParameterSets
```powershell
New-DDDesiredState [[-ScriptBlock] <scriptblock>] [-LoadPath <string>] [<CommonParameters>]
```

## DESCRIPTION
Supports loading an existing JSON configuration and/or building a configuration via a PowerShell DSL.

## EXAMPLES

### EXAMPLE 1
```powershell
PS> $cfg = New-DDDesiredState
```

Creates an in-memory configuration object with defaults and no overrides.

### EXAMPLE 2
```powershell
PS> $cfg = New-DDDesiredState -LoadPath .\desired-state.json
```

Loads a configuration from disk, allowing further in-memory changes.

### EXAMPLE 3
```powershell
PS> $cfg = New-DDDesiredState { New-DDDesiredStateDmarc -Enabled $true -AllowedPolicies reject }
```

Builds a configuration by applying profile fragments returned from the script block.

## PARAMETERS

### -LoadPath
Optional path to load an existing desired state configuration JSON file.

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

### -ScriptBlock
Optional script block that returns desired state fragments (profiles/overrides) to be applied.

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

- `DomainDetective.DesiredState.DesiredStateConfiguration`

## RELATED LINKS

- None

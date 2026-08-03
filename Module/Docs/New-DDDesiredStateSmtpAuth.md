---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# New-DDDesiredStateSmtpAuth
## SYNOPSIS
Creates an SMTP AUTH desired state policy fragment.

## SYNTAX
### __AllParameterSets
```powershell
New-DDDesiredStateSmtpAuth [-Enabled <Boolean>] [-RequireAtLeastOneResult <Boolean>] [-DisallowAuthAdvertisement <Boolean>] [-AllowedMechanisms <string[]>] [-DisallowedMechanisms <string[]>] [-RequiredMechanismsAnyOf <string[]>] [-RequireStartTlsCapabilityWhenAuth <Boolean>] [<CommonParameters>]
```

## DESCRIPTION
The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.

## EXAMPLES

### EXAMPLE 1
```powershell
PS> New-DDDesiredStateSmtpAuth -Enabled $true -RequireStartTlsCapabilityWhenAuth $true -DisallowedMechanisms NTLM,CRAM-MD5
```


## PARAMETERS

### -AllowedMechanisms
When specified, all advertised mechanisms must be within this allow list.

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

### -DisallowAuthAdvertisement
When true, disallows any SMTP AUTH advertisement on any server.

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

### -DisallowedMechanisms
When specified, none of the advertised mechanisms may be present.

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

### -Enabled
Enable/disable the SMTP AUTH desired state module.

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

### -RequireAtLeastOneResult
When true, require at least one SMTP AUTH result to be present.

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

### -RequiredMechanismsAnyOf
When specified, requires at least one of the mechanisms to be present per server advertising AUTH.

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

### -RequireStartTlsCapabilityWhenAuth
When true, requires STARTTLS capability to be advertised alongside AUTH.

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

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

- `None`

## OUTPUTS

- `DomainDetective.DesiredState.DesiredStateProfile`

## RELATED LINKS

- None

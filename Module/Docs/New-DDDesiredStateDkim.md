---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# New-DDDesiredStateDkim
## SYNOPSIS
Creates a DKIM desired state policy fragment.

## SYNTAX
### __AllParameterSets
```powershell
New-DDDesiredStateDkim [-Enabled <Boolean>] [-RequireAtLeastOneSelector <Boolean>] [-RequireStartsCorrectly <Boolean>] [-RequirePublicKey <Boolean>] [-RequireValidPublicKey <Boolean>] [-RequireValidKeyType <Boolean>] [-RequiredSelectors <string[]>] [-MinKeyBits <Int32>] [-DisallowWeakKeys <Boolean>] [-MaxKeyAgeDays <Int32>] [-DisallowDeprecatedTags <Boolean>] [-DisallowInvalidFlags <Boolean>] [-DisallowUnknownCanonicalizationModes <Boolean>] [-DisallowInvalidCanonicalization <Boolean>] [-AllowedCnameTargetSuffixes <string[]>] [<CommonParameters>]
```

## DESCRIPTION
The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.

## EXAMPLES

### EXAMPLE 1
```powershell
PS> New-DDDesiredStateDkim -Enabled $true -RequiredSelectors selector1,selector2 -MinKeyBits 2048
```


## PARAMETERS

### -AllowedCnameTargetSuffixes
Allowed domain suffixes for selector CNAME targets (vendor-hosted DKIM).

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

### -DisallowDeprecatedTags
When true, disallows deprecated DKIM tags/values.

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

### -DisallowInvalidCanonicalization
When true, disallows invalid canonicalization strings (when c= is present).

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

### -DisallowInvalidFlags
When true, disallows invalid DKIM flags.

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

### -DisallowUnknownCanonicalizationModes
When true, disallows unknown canonicalization modes.

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

### -DisallowWeakKeys
When true, disallows weak RSA keys (under 2048 bits).

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

### -Enabled
Enable/disable the DKIM desired state module.

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

### -MaxKeyAgeDays
Maximum allowed key age in days when a creation date can be inferred.

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

### -MinKeyBits
Minimum accepted key length in bits for selectors.

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

### -RequireAtLeastOneSelector
When true, requires at least one DKIM selector to be analyzed.

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

### -RequiredSelectors
Selectors that must exist and publish DKIM records (organization-specific).

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

### -RequirePublicKey
When true, requires DKIM records to contain a non-empty p= public key.

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

### -RequireStartsCorrectly
When true, requires DKIM records to start with v=DKIM1.

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

### -RequireValidKeyType
When true, requires DKIM key type to be recognized (rsa/ed25519).

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

### -RequireValidPublicKey
When true, requires DKIM public keys to be parseable/valid.

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

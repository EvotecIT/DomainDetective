---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# New-DDDesiredStateApexAddress
## SYNOPSIS
Creates an apex address desired state policy fragment.

## SYNTAX
### __AllParameterSets
```powershell
New-DDDesiredStateApexAddress [-Enabled <bool>] [-RequireAnyAddress <bool>] [-DisallowAnyAddress <bool>] [-DisallowPrivateAddresses <bool>] [-DisallowLoopbackAddresses <bool>] [-DisallowLinkLocalAddresses <bool>] [-DisallowMulticastAddresses <bool>] [-DisallowDocumentationAddresses <bool>] [-DisallowUniqueLocalV6Addresses <bool>] [-MinDistinctSubnetCountV4 <int>] [-MinDistinctSubnetCountV6 <int>] [-RequireAllPtrPresent <bool>] [-RequireAllFcrDnsValid <bool>] [<CommonParameters>]
```

## DESCRIPTION
The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.

## EXAMPLES

### EXAMPLE 1
```powershell
New-DDDesiredStateApexAddress -DisallowAnyAddress 'Value'
```


## PARAMETERS

### -DisallowAnyAddress
When true, disallows any apex A/AAAA records.

```yaml
Type: Nullable`1
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DisallowDocumentationAddresses
When true, disallow documentation/example addresses at the apex.

```yaml
Type: Nullable`1
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DisallowLinkLocalAddresses
When true, disallow link-local addresses at the apex.

```yaml
Type: Nullable`1
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DisallowLoopbackAddresses
When true, disallow loopback addresses at the apex.

```yaml
Type: Nullable`1
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DisallowMulticastAddresses
When true, disallow multicast addresses at the apex.

```yaml
Type: Nullable`1
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DisallowPrivateAddresses
When true, disallow private IPv4/IPv6 addresses at the apex.

```yaml
Type: Nullable`1
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DisallowUniqueLocalV6Addresses
When true, disallow unique-local IPv6 addresses at the apex.

```yaml
Type: Nullable`1
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
Enable/disable the apex address desired state module.

```yaml
Type: Nullable`1
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -MinDistinctSubnetCountV4
Minimum distinct subnet count for apex IPv4 addresses.

```yaml
Type: Nullable`1
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -MinDistinctSubnetCountV6
Minimum distinct subnet count for apex IPv6 addresses.

```yaml
Type: Nullable`1
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -RequireAllFcrDnsValid
When true, requires forward-confirmed reverse DNS for all discovered apex addresses.

```yaml
Type: Nullable`1
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -RequireAllPtrPresent
When true, requires PTR records to exist for all discovered apex addresses.

```yaml
Type: Nullable`1
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -RequireAnyAddress
When true, requires at least one apex A/AAAA record.

```yaml
Type: Nullable`1
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

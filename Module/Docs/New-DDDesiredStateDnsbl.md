---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# New-DDDesiredStateDnsbl
## SYNOPSIS
Creates a DNSBL desired state policy fragment.

## SYNTAX
### __AllParameterSets
```powershell
New-DDDesiredStateDnsbl [-Enabled <bool>] [-RequireAtLeastOneResult <bool>] [-DisallowListings <bool>] [-IgnoredBlacklists <string[]>] [-IncludeQueryKinds <DnsblQueryKind[]>] [-IncludeIpSources <DnsblIpSource[]>] [<CommonParameters>]
```

## DESCRIPTION
The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.

## EXAMPLES

### EXAMPLE 1
```powershell
New-DDDesiredStateDnsbl -DisallowListings 'Value'
```


## PARAMETERS

### -DisallowListings
When true, non-ignored listings are treated as drift.

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
Enable/disable the DNSBL desired state module.

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

### -IgnoredBlacklists
Blacklist domains to ignore (e.g., some providers produce false positives).

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

### -IncludeIpSources
Optional allow-list of IP sources to evaluate (MxA/MxAAAA/ApexA/ApexAAAA/Domain).

```yaml
Type: DnsblIpSource[]
Parameter Sets: __AllParameterSets
Aliases: None
Possible values: UserProvided, ApexA, ApexAAAA, MxA, MxAAAA, Domain

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -IncludeQueryKinds
Optional allow-list of query kinds to evaluate (Domain/IpAddressV4/IpAddressV6).

```yaml
Type: DnsblQueryKind[]
Parameter Sets: __AllParameterSets
Aliases: None
Possible values: Domain, IpAddress, IpAddressV4, IpAddressV6

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -RequireAtLeastOneResult
When true, warns if no DNSBL results were analyzed.

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

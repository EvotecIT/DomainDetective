---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# New-DDDesiredStateMx
## SYNOPSIS
Creates an MX desired state policy fragment.

## SYNTAX
### __AllParameterSets
```powershell
New-DDDesiredStateMx [-Enabled <bool>] [-RequireRecord <bool>] [-RequireNullMx <bool>] [-DisallowNullMx <bool>] [-RequireBackupServers <bool>] [-RequireIpv6Supported <bool>] [-AllowedHostSuffixes <string[]>] [-DisallowCnameTargets <bool>] [-DisallowIpTargets <bool>] [-DisallowNonExistentTargets <bool>] [-DisallowNoAddressTargets <bool>] [-DisallowLocalhostTargets <bool>] [-RequireTtlUniform <bool>] [-RequireRrsetConsistentAcrossNs <bool>] [-RequireTargetAddressConsistentAcrossNs <bool>] [<CommonParameters>]
```

## DESCRIPTION
The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.

## EXAMPLES

### EXAMPLE 1
```powershell
PS> New-DDDesiredStateMx -Enabled $true -RequireRecord $true -DisallowNullMx $true -AllowedHostSuffixes protection.outlook.com
```


## PARAMETERS

### -AllowedHostSuffixes
Allowed host suffixes for MX targets (e.g., protection.outlook.com).

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

### -DisallowCnameTargets
When true, disallows MX targets that resolve to CNAME.

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

### -DisallowIpTargets
When true, disallows MX targets that are raw IP addresses.

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

### -DisallowLocalhostTargets
When true, disallows MX targets that resolve to localhost.

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

### -DisallowNoAddressTargets
When true, disallows MX targets that have no A/AAAA addresses.

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

### -DisallowNonExistentTargets
When true, disallows MX targets that do not exist.

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

### -DisallowNullMx
When true, disallow a null-MX record (RFC 7505).

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
Enable/disable the MX desired state module.

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

### -RequireBackupServers
When true, requires backup servers (lower priority numbers and redundancy).

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

### -RequireIpv6Supported
When true, requires IPv6 support for MX targets.

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

### -RequireNullMx
When true, require a null-MX record (RFC 7505).

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

### -RequireRecord
When true, require an MX record to exist.

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

### -RequireRrsetConsistentAcrossNs
When true, requires RRSet consistency across authoritative name servers.

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

### -RequireTargetAddressConsistentAcrossNs
When true, requires target address consistency across authoritative name servers.

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

### -RequireTtlUniform
When true, requires MX TTL uniformity across authoritative name servers.

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

---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# New-DDDesiredStateTtl
## SYNOPSIS
Creates a DNS TTL desired state policy fragment.

## SYNTAX
### __AllParameterSets
```powershell
New-DDDesiredStateTtl [-Enabled <Boolean>] [-MinASeconds <Int32>] [-MaxASeconds <Int32>] [-MinAaaaSeconds <Int32>] [-MaxAaaaSeconds <Int32>] [-MinMxSeconds <Int32>] [-MaxMxSeconds <Int32>] [-MinNsSeconds <Int32>] [-MaxNsSeconds <Int32>] [-MinSoaSeconds <Int32>] [-MaxSoaSeconds <Int32>] [-MinSpfTxtSeconds <Int32>] [-MaxSpfTxtSeconds <Int32>] [-MinDmarcTxtSeconds <Int32>] [-MaxDmarcTxtSeconds <Int32>] [-MinDkimSelectorTxtSeconds <Int32>] [-MaxDkimSelectorTxtSeconds <Int32>] [-MinMtastsTxtSeconds <Int32>] [-MaxMtastsTxtSeconds <Int32>] [-MinTlsRptTxtSeconds <Int32>] [-MaxTlsRptTxtSeconds <Int32>] [-RequireAUniformAcrossNs <Boolean>] [-RequireAaaaUniformAcrossNs <Boolean>] [-RequireNsUniformAcrossNs <Boolean>] [-RequireCnameUniformAcrossNs <Boolean>] [-RequireSpfTxtUniformAcrossNs <Boolean>] [-RequireDmarcTxtUniformAcrossNs <Boolean>] [-RequireMtastsTxtUniformAcrossNs <Boolean>] [-RequireTlsRptTxtUniformAcrossNs <Boolean>] [-RequireDkimTxtUniformAcrossNs <Boolean>] [<CommonParameters>]
```

## DESCRIPTION
The returned object is intended to be used with New-DDDesiredState or applied to an existing configuration.

## EXAMPLES

### EXAMPLE 1
```powershell
New-DDDesiredStateTtl -Enabled $true
```


## PARAMETERS

### -Enabled
Enable/disable the TTL desired state module.

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

### -MaxAaaaSeconds
Maximum allowed TTL for AAAA records (seconds).

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

### -MaxASeconds
Maximum allowed TTL for A records (seconds).

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

### -MaxDkimSelectorTxtSeconds
Maximum allowed TTL for DKIM selector TXT records (seconds).

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

### -MaxDmarcTxtSeconds
Maximum allowed TTL for DMARC TXT records (seconds).

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

### -MaxMtastsTxtSeconds
Maximum allowed TTL for MTA-STS TXT records (seconds).

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

### -MaxMxSeconds
Maximum allowed TTL for MX records (seconds).

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

### -MaxNsSeconds
Maximum allowed TTL for NS records (seconds).

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

### -MaxSoaSeconds
Maximum allowed TTL for SOA records (seconds).

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

### -MaxSpfTxtSeconds
Maximum allowed TTL for SPF TXT records (seconds).

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

### -MaxTlsRptTxtSeconds
Maximum allowed TTL for TLS-RPT TXT records (seconds).

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

### -MinAaaaSeconds
Minimum allowed TTL for AAAA records (seconds).

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

### -MinASeconds
Minimum allowed TTL for A records (seconds).

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

### -MinDkimSelectorTxtSeconds
Minimum allowed TTL for DKIM selector TXT records (seconds).

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

### -MinDmarcTxtSeconds
Minimum allowed TTL for DMARC TXT records (seconds).

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

### -MinMtastsTxtSeconds
Minimum allowed TTL for MTA-STS TXT records (seconds).

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

### -MinMxSeconds
Minimum allowed TTL for MX records (seconds).

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

### -MinNsSeconds
Minimum allowed TTL for NS records (seconds).

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

### -MinSoaSeconds
Minimum allowed TTL for SOA records (seconds).

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

### -MinSpfTxtSeconds
Minimum allowed TTL for SPF TXT records (seconds).

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

### -MinTlsRptTxtSeconds
Minimum allowed TTL for TLS-RPT TXT records (seconds).

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

### -RequireAaaaUniformAcrossNs
When true, requires AAAA record TTL to be uniform across name servers.

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

### -RequireAUniformAcrossNs
When true, requires A record TTL to be uniform across name servers.

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

### -RequireCnameUniformAcrossNs
When true, requires CNAME record TTL to be uniform across name servers.

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

### -RequireDkimTxtUniformAcrossNs
When true, requires DKIM selector TXT record TTL to be uniform across name servers.

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

### -RequireDmarcTxtUniformAcrossNs
When true, requires DMARC TXT record TTL to be uniform across name servers.

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

### -RequireMtastsTxtUniformAcrossNs
When true, requires MTA-STS TXT record TTL to be uniform across name servers.

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

### -RequireNsUniformAcrossNs
When true, requires NS record TTL to be uniform across name servers.

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

### -RequireSpfTxtUniformAcrossNs
When true, requires SPF TXT record TTL to be uniform across name servers.

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

### -RequireTlsRptTxtUniformAcrossNs
When true, requires TLS-RPT TXT record TTL to be uniform across name servers.

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

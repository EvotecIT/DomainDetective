---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# Import-DDRegistrationSnapshot
## SYNOPSIS
Captures a unified WHOIS/RDAP registration snapshot and stores it in a time-series store.

## SYNTAX
### __AllParameterSets
```powershell
Import-DDRegistrationSnapshot [-DomainName] <string> -StorePath <string> [-DnsEndpoint <DnsEndpoint>] [-SkipRdap] [-SkipWhois] [-WhoisTimeoutSeconds <int>] [<CommonParameters>]
```

## DESCRIPTION
Queries RDAP (structured) and WHOIS (fallback/extra fields) and stores a normalized JSON snapshot on disk.

## EXAMPLES

### EXAMPLE 1
```powershell
Import-DDRegistrationSnapshot -DomainName example.com -StorePath .\Store
```


## PARAMETERS

### -DnsEndpoint
DNS endpoint used for auxiliary lookups (default System).

```yaml
Type: DnsEndpoint
Parameter Sets: __AllParameterSets
Aliases: None
Possible values: System, SystemTcp, Cloudflare, CloudflareSecurity, CloudflareFamily, CloudflareWireFormat, CloudflareWireFormatPost, CloudflareJsonPost, Google, GoogleWireFormat, GoogleWireFormatPost, GoogleJsonPost, Quad9, Quad9ECS, Quad9Unsecure, OpenDNS, OpenDNSFamily, CloudflareQuic, Quad9Http3, Quad9Quic, GoogleQuic, AdGuard, AdGuardFamily, AdGuardNonFiltering, NextDNS, DnsCryptCloudflare, DnsCryptQuad9, DnsCryptRelay, RootServer, CloudflareOdoh, Custom

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DomainName
Domain to query.

```yaml
Type: String
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: True
Position: 0
Default value: None
Accept pipeline input: True (ByValue, ByPropertyName)
Accept wildcard characters: False
```

### -SkipRdap
Skip RDAP query (use WHOIS only).

```yaml
Type: SwitchParameter
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SkipWhois
Skip WHOIS query (use RDAP only).

```yaml
Type: SwitchParameter
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -StorePath
Root directory for snapshot storage.

```yaml
Type: String
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: True
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -WhoisTimeoutSeconds
WHOIS timeout in seconds (default 30).

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

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

- `System.String`

## OUTPUTS

- `DomainDetective.TimeSeries.Registration.RegistrationSnapshot`

## RELATED LINKS

- None

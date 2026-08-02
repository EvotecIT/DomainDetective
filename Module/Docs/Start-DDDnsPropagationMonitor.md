---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# Start-DDDnsPropagationMonitor
## SYNOPSIS
Starts background monitoring of DNS propagation.

## SYNTAX
### File (Default)
```powershell
Start-DDDnsPropagationMonitor [-DomainName] <string[]> [-RecordType] <DnsRecordType> [-ServersFile <string>] [-Country <CountryId>] [-Location <LocationId>] [-IntervalSeconds <int>] [-WebhookUrl <string>] [-MaxParallelism <int>] [<CommonParameters>]
```

### Custom
```powershell
Start-DDDnsPropagationMonitor [-DomainName] <string[]> [-RecordType] <DnsRecordType> [-DnsServer <string[]>] [-Country <CountryId>] [-Location <LocationId>] [-IntervalSeconds <int>] [-WebhookUrl <string>] [-MaxParallelism <int>] [<CommonParameters>]
```

## DESCRIPTION
Part of the DomainDetective project.

## EXAMPLES

### EXAMPLE 1
```powershell
Start-DDDnsPropagationMonitor -DomainName example.com -RecordType A -WebhookUrl https://example.com/webhook
```


## PARAMETERS

### -Country
Filter builtin servers by country.

```yaml
Type: Nullable`1
Parameter Sets: File, Custom
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DnsServer
One or more custom DNS servers.

```yaml
Type: String[]
Parameter Sets: Custom
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DomainName
Domain(s) to monitor.

```yaml
Type: String[]
Parameter Sets: File, Custom
Aliases: None
Possible values:

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -IntervalSeconds
Polling interval in seconds.

```yaml
Type: Int32
Parameter Sets: File, Custom
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Location
Filter builtin servers by location.

```yaml
Type: Nullable`1
Parameter Sets: File, Custom
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -MaxParallelism
Maximum concurrent DNS queries.

```yaml
Type: Int32
Parameter Sets: File, Custom
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -RecordType
DNS record type.

```yaml
Type: DnsRecordType
Parameter Sets: File, Custom
Aliases: None
Possible values: Reserved, A, NS, MD, MF, CNAME, SOA, MB, MG, MR, NULL, WKS, PTR, HINFO, MINFO, MX, TXT, RP, AFSDB, X25, ISDN, RT, NSAP, NSAP_PTR, SIG, PX, AAAA, LOC, NXT, SRV, ATMA, NAPTR, KX, CERT, A6, DNAME, SINK, OPT, APL, DS, SSHFP, IPSECKEY, RRSIG, NSEC, DNSKEY, DHCID, NSEC3, NSEC3PARAM, TLSA, SMIMEA, HIP, NINFO, RKEY, TALINK, CDS, CDNSKEY, OPENPGPKEY, CSYNC, ZONEMD, SVCB, HTTPS, SPF, LP, TKEY, TSIG, IXFR, AXFR, MAILB, MAILA, ANY, URI, CAA, AVC, DOA, AMTRELAY, RESINFO, TA, DLV

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ServersFile
Path to JSON file with DNS servers. If omitted the file
Data/DNS/PublicDNS.json in the module directory is used when present.

```yaml
Type: String
Parameter Sets: File
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -WebhookUrl
Webhook URL for notifications.

```yaml
Type: String
Parameter Sets: File, Custom
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

- `None`

## RELATED LINKS

- None

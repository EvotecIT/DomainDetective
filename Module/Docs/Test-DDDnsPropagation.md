---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# Test-DDDnsPropagation
## SYNOPSIS
Checks how DNS records propagate across public resolvers.

## SYNTAX
### Builtin (Default)
```powershell
Test-DDDnsPropagation [-DomainName] <string[]> [-RecordType] <DnsRecordType> [-ExportFormat <ReportFormat[]>] [-ExportPath <string>] [-OpenInBrowser] [-ExportArtifacts] [-ArtifactsDirectory <string>] [-DisableParallel] [-ThrottleLimit <int>] [-MaxParallelism <int>] [-DnsParallelism <int>] [-DnsEndpoints <DnsEndpoint[]>] [-MultiResolverStrategy <MultiResolverStrategy>] [-MultiResolverMaxParallelism <int>] [-Country <CountryId>] [-Location <LocationId>] [-Take <int>] [-CountryCount <hashtable>] [-CompareResults] [-AsView] [-MaxResultsToKeep <int>] [-SnapshotPath <string>] [-Diff] [<CommonParameters>]
```

### ServersFile
```powershell
Test-DDDnsPropagation [-DomainName] <string[]> [-RecordType] <DnsRecordType> [-ServersFile] <string> [-ExportFormat <ReportFormat[]>] [-ExportPath <string>] [-OpenInBrowser] [-ExportArtifacts] [-ArtifactsDirectory <string>] [-DisableParallel] [-ThrottleLimit <int>] [-MaxParallelism <int>] [-DnsParallelism <int>] [-DnsEndpoints <DnsEndpoint[]>] [-MultiResolverStrategy <MultiResolverStrategy>] [-MultiResolverMaxParallelism <int>] [-Country <CountryId>] [-Location <LocationId>] [-Take <int>] [-CountryCount <hashtable>] [-CompareResults] [-AsView] [-MaxResultsToKeep <int>] [-SnapshotPath <string>] [-Diff] [<CommonParameters>]
```

## DESCRIPTION
Part of the DomainDetective project.

## EXAMPLES

### EXAMPLE 1
```powershell
$file = Join-Path (Split-Path ([System.Reflection.Assembly]::GetExecutingAssembly().Location)) 'Data/DNS/PublicDNS.json'; Test-DDDnsPropagation -DomainName example.com -RecordType A -ServersFile $file
```


### EXAMPLE 2
```powershell
Test-DDDnsPropagation -DomainName example.com -RecordType A -CountryCount @{PL=3;DE=2}
```


## PARAMETERS

### -ArtifactsDirectory
{{ Fill ArtifactsDirectory Description }}

```yaml
Type: String
Parameter Sets: Builtin, ServersFile
Aliases: ArtifactsPath
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -AsView
Return a typed view object suitable for composition reports.

```yaml
Type: SwitchParameter
Parameter Sets: Builtin, ServersFile
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -CompareResults
Return aggregated comparison of results.

```yaml
Type: SwitchParameter
Parameter Sets: Builtin, ServersFile
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Country
Filter servers by country.

```yaml
Type: Nullable`1
Parameter Sets: Builtin, ServersFile
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -CountryCount
Select number of servers per country.

```yaml
Type: Hashtable
Parameter Sets: Builtin, ServersFile
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Diff
Return changes since last snapshot.

```yaml
Type: SwitchParameter
Parameter Sets: Builtin, ServersFile
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DisableParallel
{{ Fill DisableParallel Description }}

```yaml
Type: SwitchParameter
Parameter Sets: Builtin, ServersFile
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DnsEndpoints
{{ Fill DnsEndpoints Description }}

```yaml
Type: DnsEndpoint[]
Parameter Sets: Builtin, ServersFile
Aliases: None
Possible values: System, SystemTcp, Cloudflare, CloudflareSecurity, CloudflareFamily, CloudflareWireFormat, CloudflareWireFormatPost, CloudflareJsonPost, Google, GoogleWireFormat, GoogleWireFormatPost, GoogleJsonPost, Quad9, Quad9ECS, Quad9Unsecure, OpenDNS, OpenDNSFamily, CloudflareQuic, Quad9Http3, Quad9Quic, GoogleQuic, AdGuard, AdGuardFamily, AdGuardNonFiltering, NextDNS, DnsCryptCloudflare, DnsCryptQuad9, DnsCryptRelay, RootServer, CloudflareOdoh, Custom

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DnsParallelism
{{ Fill DnsParallelism Description }}

```yaml
Type: Nullable`1
Parameter Sets: Builtin, ServersFile
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DomainName
Domain(s) to query.

```yaml
Type: String[]
Parameter Sets: Builtin, ServersFile
Aliases: None
Possible values:

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ExportArtifacts
{{ Fill ExportArtifacts Description }}

```yaml
Type: SwitchParameter
Parameter Sets: Builtin, ServersFile
Aliases: Artifacts
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ExportFormat
{{ Fill ExportFormat Description }}

```yaml
Type: ReportFormat[]
Parameter Sets: Builtin, ServersFile
Aliases: Report
Possible values: Html, Json, Word, Excel, Markdown, MarkdownHtml

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ExportPath
{{ Fill ExportPath Description }}

```yaml
Type: String
Parameter Sets: Builtin, ServersFile
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Location
Filter servers by location.

```yaml
Type: Nullable`1
Parameter Sets: Builtin, ServersFile
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -MaxParallelism
{{ Fill MaxParallelism Description }}

```yaml
Type: Nullable`1
Parameter Sets: Builtin, ServersFile
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -MaxResultsToKeep
Maximum number of resolver results retained in the view (default: 500).

```yaml
Type: Int32
Parameter Sets: Builtin, ServersFile
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -MultiResolverMaxParallelism
{{ Fill MultiResolverMaxParallelism Description }}

```yaml
Type: Nullable`1
Parameter Sets: Builtin, ServersFile
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -MultiResolverStrategy
{{ Fill MultiResolverStrategy Description }}

```yaml
Type: MultiResolverStrategy
Parameter Sets: Builtin, ServersFile
Aliases: None
Possible values: FirstSuccess, FastestWins, SequentialFallback, RoundRobin, Random

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -OpenInBrowser
{{ Fill OpenInBrowser Description }}

```yaml
Type: SwitchParameter
Parameter Sets: Builtin, ServersFile
Aliases: OpenReport
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -RecordType
DNS record type to test.

```yaml
Type: DnsRecordType
Parameter Sets: Builtin, ServersFile
Aliases: None
Possible values: Reserved, A, NS, MD, MF, CNAME, SOA, MB, MG, MR, NULL, WKS, PTR, HINFO, MINFO, MX, TXT, RP, AFSDB, X25, ISDN, RT, NSAP, NSAP_PTR, SIG, PX, AAAA, LOC, NXT, SRV, ATMA, NAPTR, KX, CERT, A6, DNAME, SINK, OPT, APL, DS, SSHFP, IPSECKEY, RRSIG, NSEC, DNSKEY, DHCID, NSEC3, NSEC3PARAM, TLSA, SMIMEA, HIP, NINFO, RKEY, TALINK, CDS, CDNSKEY, OPENPGPKEY, CSYNC, ZONEMD, SVCB, HTTPS, SPF, LP, TKEY, TSIG, IXFR, AXFR, MAILB, MAILA, ANY, URI, CAA, AVC, DOA, AMTRELAY, RESINFO, TA, DLV

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ServersFile
Path to JSON file with DNS servers.

```yaml
Type: String
Parameter Sets: ServersFile
Aliases: None
Possible values:

Required: True
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SnapshotPath
Directory used to store DNS snapshots.

```yaml
Type: String
Parameter Sets: Builtin, ServersFile
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Take
Limit the number of servers queried.

```yaml
Type: Nullable`1
Parameter Sets: Builtin, ServersFile
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ThrottleLimit
{{ Fill ThrottleLimit Description }}

```yaml
Type: Nullable`1
Parameter Sets: Builtin, ServersFile
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

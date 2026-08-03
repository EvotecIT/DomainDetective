---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# Test-DDDnsBlacklist
## SYNOPSIS
Queries DNSBL providers to see if domains or IPs are listed.

## SYNTAX
### ServerName (Default)
```powershell
Test-DDDnsBlacklist [-NameOrIpAddress] <string[]> [[-DnsEndpoint] <DnsEndpoint>] [-BlacklistedOnly] [-TreatAsDomain] [-TreatAsIp] [-MaxConcurrency <Int32>] [-DomainIpScan <DomainIpScanMode>] [-ExportFormat <ReportFormat[]>] [-ExportPath <string>] [-OpenInBrowser] [-ExportArtifacts] [-ArtifactsDirectory <string>] [-DisableParallel] [-ThrottleLimit <Int32>] [-MaxParallelism <Int32>] [-DnsParallelism <Int32>] [-DnsEndpoints <DnsEndpoint[]>] [-MultiResolverStrategy <MultiResolverStrategy>] [-MultiResolverMaxParallelism <Int32>] [-FullResponse] [<CommonParameters>]
```

## DESCRIPTION
Default behavior:
- Domain inputs: queries domain blocklists and then resolves MX A/AAAA to query IP blocklists for each resulting IP.
- IP inputs: queries IP blocklists directly.
- Mixed arrays: aggregates both without clearing prior results.
Overrides:
- -TreatAsDomain: forces the "domain + MX-IP" path for the input(s).
- -TreatAsIp: if an input is an IP it is checked as-is; if an input is a domain, its apex A/AAAA IPs are resolved and checked on IP blocklists.
Fallback:
- When MX exists but has no resolvable A/AAAA (or no MX is present), the cmdlet falls back to apex A/AAAA for IP blocklist checks.
Output:
- By default returns a summary view across the domain and any resolved IPs.
- With -FullResponse returns a dictionary mapping each key (domain or IP) to a DNSQueryResult.
- Use -BlacklistedOnly to filter output to listed results.
Performance:
- Use -MaxConcurrency to hint the DNS resolver concurrency (requires DnsClientX 1.0.1+).
Domain IP scan control:
- Use -DomainIpScan to control which IPs are resolved and checked when a domain is provided.
Values: MxOnly, MxAOnly, MxAAAAOnly, ApexOnly, ApexAOnly, ApexAAAAOnly, MxAndApex, MxThenApexFallback (default).
Notes:
- Word and HTML composition exports are supported.
- Other export formats continue to use the shared "not implemented" warning path.

## EXAMPLES

### EXAMPLE 1
```powershell
Test-DDDnsBlacklist -NameOrIpAddress 'example.com' -Verbose
```


### EXAMPLE 2
```powershell
Test-DDDnsBlacklist -NameOrIpAddress 'example.com' -TreatAsDomain -Verbose
```


### EXAMPLE 3
```powershell
Test-DDDnsBlacklist -NameOrIpAddress 'example.com' -TreatAsIp -Verbose
```


### EXAMPLE 4
```powershell
Test-DDDnsBlacklist -NameOrIpAddress 'example.com','203.0.113.10' -BlacklistedOnly
```


### EXAMPLE 5
```powershell
$res = Test-DDDnsBlacklist -NameOrIpAddress 'example.com' -FullResponse; $res['example.com']
```


### EXAMPLE 6
```powershell
Test-DDDnsBlacklist -NameOrIpAddress 'example.com' -MaxConcurrency 64 -Verbose
```


## PARAMETERS

### -ArtifactsDirectory
Destination directory for artifacts when emitted.

```yaml
Type: String
Parameter Sets: ServerName
Aliases: ArtifactsPath
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -BlacklistedOnly
Return only blacklisted results.

```yaml
Type: SwitchParameter
Parameter Sets: ServerName
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DisableParallel
Disable parallel execution for cmdlet-level work.

```yaml
Type: SwitchParameter
Parameter Sets: ServerName
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DnsEndpoint
DNS server used for queries.

```yaml
Type: DnsEndpoint
Parameter Sets: ServerName
Aliases: None
Possible values: System, SystemTcp, Cloudflare, CloudflareSecurity, CloudflareFamily, CloudflareWireFormat, CloudflareWireFormatPost, CloudflareJsonPost, Google, GoogleWireFormat, GoogleWireFormatPost, GoogleJsonPost, Quad9, Quad9ECS, Quad9Unsecure, OpenDNS, OpenDNSFamily, CloudflareQuic, Quad9Http3, Quad9Quic, GoogleQuic, AdGuard, AdGuardFamily, AdGuardNonFiltering, NextDNS, DnsCryptCloudflare, DnsCryptQuad9, DnsCryptRelay, RootServer, CloudflareOdoh, Custom

Required: False
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DnsEndpoints
Optional list of resolver endpoints to use (multi-resolver).

```yaml
Type: DnsEndpoint[]
Parameter Sets: ServerName
Aliases: None
Possible values: System, SystemTcp, Cloudflare, CloudflareSecurity, CloudflareFamily, CloudflareWireFormat, CloudflareWireFormatPost, CloudflareJsonPost, Google, GoogleWireFormat, GoogleWireFormatPost, GoogleJsonPost, Quad9, Quad9ECS, Quad9Unsecure, OpenDNS, OpenDNSFamily, CloudflareQuic, Quad9Http3, Quad9Quic, GoogleQuic, AdGuard, AdGuardFamily, AdGuardNonFiltering, NextDNS, DnsCryptCloudflare, DnsCryptQuad9, DnsCryptRelay, RootServer, CloudflareOdoh, Custom

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DnsParallelism
DNS resolver concurrency hint for health checks.

```yaml
Type: Int32
Parameter Sets: ServerName
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DomainIpScan
Controls which IPs are resolved and checked for domains.

```yaml
Type: DomainIpScanMode
Parameter Sets: ServerName
Aliases: None
Possible values: MxOnly, MxAOnly, MxAAAAOnly, ApexOnly, ApexAOnly, ApexAAAAOnly, MxAndApex, MxThenApexFallback

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ExportArtifacts
Emit artifacts (scan.json, metrics.json, progress.jsonl).

```yaml
Type: SwitchParameter
Parameter Sets: ServerName
Aliases: Artifacts
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ExportFormat
Desired export format(s). Accepts one or many values.

```yaml
Type: ReportFormat[]
Parameter Sets: ServerName
Aliases: Report
Possible values: Html, Json, Word, Excel, Markdown, MarkdownHtml

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ExportPath
Output file path for export.

```yaml
Type: String
Parameter Sets: ServerName
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -FullResponse
Return full analysis result.

```yaml
Type: SwitchParameter
Parameter Sets: ServerName
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -MaxConcurrency
Max concurrency hint for resolver (if supported).

```yaml
Type: Int32
Parameter Sets: ServerName
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -MaxParallelism
Maximum concurrent health checks within a single domain run.

```yaml
Type: Int32
Parameter Sets: ServerName
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -MultiResolverMaxParallelism
Maximum number of resolvers to query in parallel (null = all).

```yaml
Type: Int32
Parameter Sets: ServerName
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -MultiResolverStrategy
Strategy used when multiple DNS endpoints are provided.

```yaml
Type: MultiResolverStrategy
Parameter Sets: ServerName
Aliases: None
Possible values: FirstSuccess, FastestWins, SequentialFallback, RoundRobin, Random

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -NameOrIpAddress
Domain names or IP addresses to check.

```yaml
Type: String[]
Parameter Sets: ServerName
Aliases: None
Possible values:

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -OpenInBrowser
Open export in browser when applicable.

```yaml
Type: SwitchParameter
Parameter Sets: ServerName
Aliases: OpenReport
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ThrottleLimit
Maximum number of concurrent items for cmdlet-level parallel work.

```yaml
Type: Int32
Parameter Sets: ServerName
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -TreatAsDomain
Force domain-mode queries (domain + MX IPs).

```yaml
Type: SwitchParameter
Parameter Sets: ServerName
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -TreatAsIp
Force IP-mode queries (input must be IP).

```yaml
Type: SwitchParameter
Parameter Sets: ServerName
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

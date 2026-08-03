---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# Test-DDDomainOverallHealth
## SYNOPSIS
Runs multiple domain health checks and returns the results.

## SYNTAX
### ServerName (Default)
```powershell
Test-DDDomainOverallHealth [-DomainName] <string[]> [[-DnsEndpoint] <DnsEndpoint>] [-ExportFormat <ReportFormat[]>] [-ExportPath <string>] [-OpenInBrowser] [-ExportArtifacts] [-ArtifactsDirectory <string>] [-DisableParallel] [-ThrottleLimit <Int32>] [-MaxParallelism <Int32>] [-DnsParallelism <Int32>] [-DnsEndpoints <DnsEndpoint[]>] [-MultiResolverStrategy <MultiResolverStrategy>] [-MultiResolverMaxParallelism <Int32>] [-HealthCheckType <HealthCheckType[]>] [-DkimSelectors <string[]>] [-DaneServiceType <ServiceType[]>] [-DanePorts <int[]>] [-BrandKeyword <string[]>] [-PortScanProfile <PortScanProfileDefinition+PortScanProfile[]>] [<CommonParameters>]
```

## DESCRIPTION
Part of the DomainDetective project.

## EXAMPLES

### EXAMPLE 1
```powershell
Test-DDDomainOverallHealth -DomainName example.com -Verbose
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

### -BrandKeyword
Protected brand terms for typosquatting analysis.

```yaml
Type: String[]
Parameter Sets: ServerName
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DanePorts
Custom ports to check for DANE.

```yaml
Type: Int32[]
Parameter Sets: ServerName
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DaneServiceType
Service types to check for DANE. HTTPS (port 443) is queried by default.

```yaml
Type: ServiceType[]
Parameter Sets: ServerName
Aliases: None
Possible values: SMTP, HTTPS

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

### -DkimSelectors
DKIM selectors used when testing DKIM.

```yaml
Type: String[]
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

### -DomainName
Domain(s) to analyze.

```yaml
Type: String[]
Parameter Sets: ServerName
Aliases: None
Possible values:

Required: True
Position: 0
Default value: None
Accept pipeline input: True (ByValue, ByPropertyName)
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

### -HealthCheckType
Specific tests to run.

```yaml
Type: HealthCheckType[]
Parameter Sets: ServerName
Aliases: None
Possible values: DMARC, SPF, DKIM, MX, REVERSEDNS, FCRDNS, CAA, NS, DELEGATION, ZONETRANSFER, DANE, SMIMEA, DNSBL, DNSSEC, MTASTS, TLSRPT, BIMI, AUTODISCOVER, CERT, SECURITYTXT, ROBOTS, SOA, OPENRELAY, OPENRESOLVER, STARTTLS, SMTPTLS, IMAPTLS, POP3TLS, SMTPBANNER, SMTPAUTH, HTTP, HPKP, CONTACT, MESSAGEHEADER, ARC, DANGLINGCNAME, TTL, PORTAVAILABILITY, PORTSCAN, SNMP, IPNEIGHBOR, IPENRICHMENT, RPKI, DNSTUNNELING, TYPOSQUATTING, THREATINTEL, THREATFEED, WILDCARDDNS, EDNSSUPPORT, DNSHEALTH, MAILLATENCY, FLATTENINGSERVICE, RDAP, DIRECTORYEXPOSURE, NTP, WEBSITE, WHOIS, APEXADDRESS, SPFFLATTENED, MAILCLASSIFICATION, SUBDOMAINS, DNSINVENTORY, DNSTRACE, CTTIMELINE, DNSPROPAGATION, DNSAMPLIFICATION, DNSOVERTLS, IDENTITYPROVIDER, MICROSOFT365, SITEMAP, AGENTREADINESS

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

### -PortScanProfile
Port scan profiles to use.

```yaml
Type: PortScanProfile[]
Parameter Sets: ServerName
Aliases: None
Possible values: Default, SMB, NTP, RADIUS

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

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

- `System.String[]`

## OUTPUTS

- `DomainDetective.Views.DomainOverallInfo`

## RELATED LINKS

- None

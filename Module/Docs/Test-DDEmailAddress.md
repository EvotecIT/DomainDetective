---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# Test-DDEmailAddress
## SYNOPSIS
Validates an email address using syntax, DNS, and optional SMTP checks.

## SYNTAX
### __AllParameterSets
```powershell
Test-DDEmailAddress [-EmailAddress] <string> [[-DnsEndpoint] <DnsEndpoint>] [-ExportFormat <ReportFormat[]>] [-ExportPath <string>] [-OpenInBrowser] [-ExportArtifacts] [-ArtifactsDirectory <string>] [-DisableParallel] [-ThrottleLimit <Int32>] [-MaxParallelism <Int32>] [-DnsParallelism <Int32>] [-DnsEndpoints <DnsEndpoint[]>] [-MultiResolverStrategy <MultiResolverStrategy>] [-MultiResolverMaxParallelism <Int32>] [-AllowInternational] [-AllowTopLevelDomains] [-SmtpProbe] [-CheckCatchAll] [-SmtpPort <int>] [-SmtpTimeoutSeconds <int>] [-AllowInvalidSmtpCertificates] [-SmtpProbeDelaySeconds <int>] [-SmtpMaxHosts <int>] [-SmtpRetryCount <int>] [-SmtpRetryDelaySeconds <int>] [-SmtpHelloName <string>] [-SmtpFromAddress <string>] [-SmtpProxyHost <string>] [-SmtpProxyPort <int>] [-SmtpProxyUsername <string>] [-SmtpProxyPassword <string>] [-CheckGravatar] [-DisableProviderRules] [-CheckHaveIBeenPwned] [-HaveIBeenPwnedApiKey <string>] [-DisposableDomainsPath <string>] [-RoleAccountsPath <string>] [-FreeProvidersPath <string>] [-B2CProvidersPath <string>] [-DisableFreeProvidersAsB2C] [-SmtpRulesPath <string>] [-DisableBuiltinSmtpRules] [-AllowB2CCatchAll] [-EnableProviderWebChecks] [-ProtonAuthCookie <string>] [-ProtonUid <string>] [<CommonParameters>]
```

## DESCRIPTION
Part of the DomainDetective project.

## EXAMPLES

### EXAMPLE 1
```powershell
Test-DDEmailAddress -EmailAddress user@example.com
```


### EXAMPLE 2
```powershell
Test-DDEmailAddress -EmailAddress user@example.com -SmtpProbe -CheckCatchAll
```


### EXAMPLE 3
```powershell
Test-DDEmailAddress -EmailAddress user@proton.me -SmtpProbe -EnableProviderWebChecks -ProtonAuthCookie "AUTH-<uid>=<value>" -ProtonUid "<uid>"
```


## PARAMETERS

### -AllowB2CCatchAll
Allow catch-all probing for B2C providers.

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

### -AllowInternational
Allow international characters in local parts.

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

### -AllowInvalidSmtpCertificates
Allow invalid SMTP TLS certificates when STARTTLS is used.

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

### -AllowTopLevelDomains
Allow top-level-only domains.

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

### -ArtifactsDirectory
Destination directory for artifacts when emitted.

```yaml
Type: String
Parameter Sets: __AllParameterSets
Aliases: ArtifactsPath
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -B2CProvidersPath
Override B2C provider list path.

```yaml
Type: String
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -CheckCatchAll
Enable catch-all detection when SMTP probing.

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

### -CheckGravatar
Check for an existing Gravatar image.

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

### -CheckHaveIBeenPwned
Check Have I Been Pwned breach status.

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

### -DisableBuiltinSmtpRules
Disable built-in SMTP rules.

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

### -DisableFreeProvidersAsB2C
Do not treat free providers as B2C.

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

### -DisableParallel
Disable parallel execution for cmdlet-level work.

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

### -DisableProviderRules
Disable provider-specific SMTP rules.

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

### -DisposableDomainsPath
Override disposable domain list path.

```yaml
Type: String
Parameter Sets: __AllParameterSets
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
Parameter Sets: __AllParameterSets
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
Parameter Sets: __AllParameterSets
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
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -EmailAddress
Email address to validate.

```yaml
Type: String
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -EnableProviderWebChecks
Enable provider web checks when available.

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

### -ExportArtifacts
Emit artifacts (scan.json, metrics.json, progress.jsonl).

```yaml
Type: SwitchParameter
Parameter Sets: __AllParameterSets
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
Parameter Sets: __AllParameterSets
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
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -FreeProvidersPath
Override free provider list path.

```yaml
Type: String
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -HaveIBeenPwnedApiKey
Have I Been Pwned API key.

```yaml
Type: String
Parameter Sets: __AllParameterSets
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
Parameter Sets: __AllParameterSets
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
Parameter Sets: __AllParameterSets
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
Parameter Sets: __AllParameterSets
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
Parameter Sets: __AllParameterSets
Aliases: OpenReport
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ProtonAuthCookie
Proton AUTH cookie value (AUTH-<uid> or raw value).

```yaml
Type: String
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ProtonUid
Proton uid value used for x-pm-uid.

```yaml
Type: String
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -RoleAccountsPath
Override role account list path.

```yaml
Type: String
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SmtpFromAddress
MAIL FROM address to use.

```yaml
Type: String
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SmtpHelloName
EHLO/HELO name to present.

```yaml
Type: String
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SmtpMaxHosts
Max SMTP hosts to try.

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

### -SmtpPort
SMTP port for probing.

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

### -SmtpProbe
Enable SMTP probe for deliverability.

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

### -SmtpProbeDelaySeconds
Delay between SMTP probe attempts in seconds.

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

### -SmtpProxyHost
SMTP proxy host (SOCKS5).

```yaml
Type: String
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SmtpProxyPassword
SMTP proxy password (SOCKS5).

```yaml
Type: String
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SmtpProxyPort
SMTP proxy port (SOCKS5).

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

### -SmtpProxyUsername
SMTP proxy username (SOCKS5).

```yaml
Type: String
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SmtpRetryCount
SMTP retries on temporary failures.

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

### -SmtpRetryDelaySeconds
SMTP retry delay in seconds.

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

### -SmtpRulesPath
SMTP rules JSON path.

```yaml
Type: String
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SmtpTimeoutSeconds
SMTP timeout in seconds.

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

### -ThrottleLimit
Maximum number of concurrent items for cmdlet-level parallel work.

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

- `None`

## OUTPUTS

- `None`

## RELATED LINKS

- None

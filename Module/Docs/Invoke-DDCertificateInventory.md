---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# Invoke-DDCertificateInventory
## SYNOPSIS
Captures and optionally persists a certificate inventory snapshot from domains and discovered endpoints.

## SYNTAX
### __AllParameterSets
```powershell
Invoke-DDCertificateInventory [[-DomainName] <string[]>] [-DomainsFile <string>] [-CacheDirectory <string>] [-DnsEndpoint <DnsEndpoint>] [-NoApexHttps] [-NoWwwHttps] [-IncludeMxHttps] [-DisableMxDiscovery] [-DisableSmtpStartTls] [-DisableSubmissionStartTls] [-IncludeImapTls] [-IncludePop3Tls] [-IncludeCtSubdomains] [-VerifyCtSubdomains] [-MaxCtRowsPerDomain <int>] [-MaxCtSubdomainsPerDomain <int>] [-EnableNativeCtLogSubdomains] [-DisableNativeCtSharedIngestion] [-NativeCtLogOnly] [-EnablePassiveCtFallback] [-EnablePassiveCtMetadataFallback] [-NativeCtLogListUrl <string>] [-NativeCtLogUrl <string[]>] [-NativeCtMaxLogs <int>] [-NativeCtMaxEntriesPerLog <int>] [-NativeCtEntryBatchSize <int>] [-NativeCtInitialBackfillEntriesPerLog <int>] [-NativeCtCursorStatePath <string>] [-NativeCtIncludePendingLogs] [-NativeCtRequestDelayMilliseconds <int>] [-NativeCtRetryCount <int>] [-NativeCtRetryBaseDelayMilliseconds <int>] [-NativeCtRetryMaxDelayMilliseconds <int>] [-NativeCtCircuitBreakerFailureThreshold <int>] [-NativeCtCircuitBreakerDurationSeconds <int>] [-DisableNativeCtCatchUpMode] [-NativeCtCatchUpLagThreshold <int>] [-NativeCtCatchUpMaxEntriesPerLog <int>] [-NativeCtCatchUpBatchSize <int>] [-Endpoint <string[]>] [-MaxMxHostsPerDomain <int>] [-MaxParallelism <int>] [-DiscoveryParallelism <int>] [-MailTimeoutSeconds <int>] [-HttpsTimeoutSeconds <int>] [-MaxProbeErrorWarnings <int>] [-MaxTargets <int>] [-MaxProbeStartsPerSecond <int>] [-ReuseRecentResults] [-RecentResultTtlHours <int>] [-ReuseRecentFailureResults] [-RecentFailureResultTtlHours <int>] [-ReprobeExpiringWithinDays <int>] [-SkipRevocation] [-CtProfile <CertificateCtEnrichmentProfile>] [-DisableDefaultCtTemplate] [-CtApiTemplate <string[]>] [-EnableCensysCtSource] [-CensysApiId <string>] [-CensysApiSecret <string>] [-CensysApiSecretEnv <string>] [-CensysCtApiUrlTemplate <string>] [-EnableShodanCtSource] [-ShodanApiKey <string>] [-ShodanApiKeyEnv <string>] [-ShodanCtApiUrlTemplate <string>] [-NoPersist] [-FailOnWarningTargetDecisions] [<CommonParameters>]
```

## DESCRIPTION
Discovers HTTPS and mail TLS endpoints (for example MX-derived STARTTLS) and stores normalized certificate evidence in the inventory snapshot format used by certificate inventory analytics cmdlets.

## EXAMPLES

### EXAMPLE 1
```powershell
Invoke-DDCertificateInventory -DomainName evotec.xyz,evotec.pl -CacheDirectory .\cert-monitor
```


### EXAMPLE 2
```powershell
Invoke-DDCertificateInventory -DomainsFile .\domains.txt -Endpoint https://api.example.com:8443
```


### EXAMPLE 3
```powershell
Invoke-DDCertificateInventory -DomainName example.com -CtProfile Extended -EnableShodanCtSource -ShodanApiKeyEnv SHODAN_API_KEY
```


### EXAMPLE 4
```powershell
Invoke-DDCertificateInventory -DomainName eurofins.com -IncludeCtSubdomains -VerifyCtSubdomains -MaxCtSubdomainsPerDomain 5000 -Verbose
```


### EXAMPLE 5
```powershell
Invoke-DDCertificateInventory -DomainName eurofins.com -IncludeCtSubdomains -EnableNativeCtLogSubdomains -NativeCtLogOnly -NativeCtInitialBackfillEntriesPerLog 5000 -Verbose
```


### EXAMPLE 6
```powershell
Invoke-DDCertificateInventory -DomainName eurofins.com -IncludeCtSubdomains -Limit 150 -MaxProbeStartsPerSecond 20 -MaxProbeErrorWarnings 10 -Verbose
```


### EXAMPLE 7
```powershell
Invoke-DDCertificateInventory -DomainName eurofins.com -IncludeCtSubdomains -ReuseRecentResults -RecentResultTtlHours 24 -ReprobeExpiringWithinDays 14
```


### EXAMPLE 8
```powershell
Invoke-DDCertificateInventory -DomainName eurofins.com -ReuseRecentFailureResults -RecentFailureResultTtlHours 1 -HttpsTimeoutSeconds 20
```


### EXAMPLE 9
```powershell
Invoke-DDCertificateInventory -DomainName example.com -Endpoint ftp://example.com -FailOnWarningTargetDecisions
```


## PARAMETERS

### -CacheDirectory
Certificate monitor cache directory containing the inventory folder.

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

### -CensysApiId
Censys API identifier.

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

### -CensysApiSecret
Censys API secret. Prefer CensysApiSecretEnv for safer automation.

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

### -CensysApiSecretEnv
Environment variable name containing Censys API secret.

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

### -CensysCtApiUrlTemplate
Censys CT API URL template containing a {0} fingerprint placeholder.

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

### -CtApiTemplate
Additional CT API templates (must include a {0} fingerprint placeholder).

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

### -CtProfile
CT enrichment profile. Values: Default, Disabled, Public, Extended.

```yaml
Type: CertificateCtEnrichmentProfile
Parameter Sets: __AllParameterSets
Aliases: None
Possible values: Default, Disabled, Public, Extended

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DisableDefaultCtTemplate
Disable the default crt.sh template during CT lookups.

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

### -DisableMxDiscovery
Disable MX discovery from DNS.

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

### -DisableNativeCtCatchUpMode
Disable native CT catch-up mode that expands limits when cursor lag is high.

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

### -DisableNativeCtSharedIngestion
Disable shared native CT ingestion pass across all domains (uses per-domain native CT discovery instead).

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

### -DisableSmtpStartTls
Disable SMTP STARTTLS probing on port 25.

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

### -DisableSubmissionStartTls
Disable SMTP STARTTLS probing on submission port 587.

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

### -DiscoveryParallelism
Maximum concurrent domain discovery operations.

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

### -DnsEndpoint
DNS endpoint used for MX discovery.

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
Domain list to scan. Can be provided from pipeline.

```yaml
Type: String[]
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: 0
Default value: None
Accept pipeline input: True (ByValue, ByPropertyName)
Accept wildcard characters: False
```

### -DomainsFile
Optional text file with domains/endpoints (one per line).

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

### -EnableCensysCtSource
Enable Censys CT source.

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

### -EnableNativeCtLogSubdomains
Enable native RFC6962 CT log polling for CT subdomain discovery.

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

### -EnablePassiveCtFallback
Enable passive/public CT fallback for CT subdomain discovery.

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

### -EnablePassiveCtMetadataFallback
Enable passive/public CT metadata rescue without broadly enabling passive CT discovery fallback.

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

### -EnableShodanCtSource
Enable Shodan CT source.

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

### -Endpoint
Additional endpoint(s) to probe (supports https:// and mail schemes).

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

### -FailOnWarningTargetDecisions
When set, throw a terminating error when warning-level target-decision buckets are present.

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

### -HttpsTimeoutSeconds
HTTPS certificate probe timeout in seconds.

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

### -IncludeCtSubdomains
Discover CT-observed subdomains for each input domain and probe them over HTTPS.

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

### -IncludeImapTls
Enable IMAP TLS probing on port 993.

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

### -IncludeMxHttps
Enable HTTPS probing for discovered MX hosts.

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

### -IncludePop3Tls
Enable POP3 TLS probing on port 995.

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

### -MailTimeoutSeconds
Mail TLS timeout in seconds.

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

### -MaxCtRowsPerDomain
Maximum CT rows processed per domain when CT subdomain discovery is enabled (0 means no explicit cap override).

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

### -MaxCtSubdomainsPerDomain
Maximum CT subdomains retained per domain when CT subdomain discovery is enabled (0 means no explicit cap override).

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

### -MaxMxHostsPerDomain
Maximum MX hosts retained per domain (0 means unlimited).

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

### -MaxParallelism
Maximum concurrent probe operations.

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

### -MaxProbeErrorWarnings
Maximum number of detailed endpoint probe error warnings to emit (0 emits only a summary warning).

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

### -MaxProbeStartsPerSecond
Maximum number of probe starts per second (0 means unlimited).

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

### -MaxTargets
Maximum total probe targets (HTTPS + mail) kept after discovery; useful for quick test runs (0 means unlimited).

```yaml
Type: Int32
Parameter Sets: __AllParameterSets
Aliases: Limit
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -NativeCtCatchUpBatchSize
Maximum get-entries batch size while native CT catch-up mode is active.

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

### -NativeCtCatchUpLagThreshold
Native CT cursor lag threshold that enables catch-up mode.

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

### -NativeCtCatchUpMaxEntriesPerLog
Maximum CT entries processed per log while native CT catch-up mode is active.

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

### -NativeCtCircuitBreakerDurationSeconds
Native CT circuit-breaker open duration in seconds.

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

### -NativeCtCircuitBreakerFailureThreshold
Consecutive native CT failures required before opening the per-log circuit breaker.

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

### -NativeCtCursorStatePath
Optional native CT cursor state file path (defaults to inventory/ct-native-cursor.json under CacheDirectory).

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

### -NativeCtEntryBatchSize
Maximum get-entries batch size when native CT polling is enabled.

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

### -NativeCtIncludePendingLogs
Include pending CT logs when using native CT log list ingestion.

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

### -NativeCtInitialBackfillEntriesPerLog
Initial per-log backfill when no native CT cursor exists (0 starts at current tree head).

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

### -NativeCtLogListUrl
Native CT log list URL used to resolve CT logs.

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

### -NativeCtLogOnly
Use only native CT log polling for CT subdomain discovery (skip crt.sh/Cert Spotter).

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

### -NativeCtLogUrl
Optional explicit CT log URL list for native CT polling.

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

### -NativeCtMaxEntriesPerLog
Maximum CT entries processed per log per domain when native CT polling is enabled.

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

### -NativeCtMaxLogs
Maximum CT logs processed per domain when native CT polling is enabled.

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

### -NativeCtRequestDelayMilliseconds
Optional delay in milliseconds between native CT requests.

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

### -NativeCtRetryBaseDelayMilliseconds
Base delay in milliseconds between native CT retry attempts.

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

### -NativeCtRetryCount
Maximum retry count for transient native CT HTTP failures.

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

### -NativeCtRetryMaxDelayMilliseconds
Maximum delay in milliseconds between native CT retry attempts.

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

### -NoApexHttps
Do not probe apex domains over HTTPS.

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

### -NoPersist
Do not persist snapshot file; only return in-memory result.

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

### -NoWwwHttps
Do not probe www.<domain> over HTTPS.

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

### -RecentFailureResultTtlHours
How old persisted stable failure entries can be to qualify for reuse.

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

### -RecentResultTtlHours
How old persisted snapshot entries can be to qualify for reuse.

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

### -ReprobeExpiringWithinDays
Always re-probe endpoints with certificates expiring within this many days.

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

### -ReuseRecentFailureResults
Reuse recent persisted stable failures to avoid immediately re-probing dead or timeout-heavy endpoints.

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

### -ReuseRecentResults
Reuse recent persisted endpoint results to avoid re-probing unchanged endpoints.

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

### -ShodanApiKey
Shodan API key. Prefer ShodanApiKeyEnv for safer automation.

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

### -ShodanApiKeyEnv
Environment variable name containing Shodan API key.

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

### -ShodanCtApiUrlTemplate
Shodan CT API URL template containing {0} fingerprint and {1} API key placeholders.

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

### -SkipRevocation
Skip revocation checks for HTTPS probes.

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

### -VerifyCtSubdomains
When used with -IncludeCtSubdomains, only include CT subdomains that currently resolve in DNS.

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

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

- `System.String[]`

## OUTPUTS

- `DomainDetective.CertificateInventoryCaptureResult`

## RELATED LINKS

- None

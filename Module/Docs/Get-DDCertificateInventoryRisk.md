---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# Get-DDCertificateInventoryRisk
## SYNOPSIS
Builds endpoint-level certificate risk posture from persisted inventory snapshots.

## SYNTAX
### __AllParameterSets
```powershell
Get-DDCertificateInventoryRisk [-CacheDirectory <string>] [-SinceUtc <datetime>] [-IncludeHealthy] [-ExpiringWithinDays <int>] [-CriticalExpiringWithinDays <int>] [-MaxEndpoints <int>] [-MinimumSeverity <string>] [-ScoreMin <int>] [-ScoreMax <int>] [-ReasonCountMin <int>] [-ReasonCountMax <int>] [-ReuseEndpointCountMin <int>] [-ReuseEndpointCountMax <int>] [-RiskProfile <string>] [-ReasonContains <string>] [-ReasonAnyOf <string[]>] [-ReasonAllOf <string[]>] [-IssuerContains <string>] [-IssuerContainsAnyOf <string[]>] [-IssuerContainsAllOf <string[]>] [-RootIssuerContains <string>] [-RootIssuerContainsAnyOf <string[]>] [-RootIssuerContainsAllOf <string[]>] [-AuthorityFamilyEquals <string>] [-RootAuthorityFamilyEquals <string>] [-CtSourceContains <string>] [-CtTemplateErrorContains <string>] [-ChainSourceContains <string>] [-ThumbprintEquals <string>] [-RootThumbprintEquals <string>] [-SerialNumberEquals <string>] [-HostContains <string>] [-ServiceEquals <string>] [-PortEquals <int>] [-ChainLengthMin <int>] [-ChainLengthMax <int>] [-IntermediateCountMin <int>] [-IntermediateCountMax <int>] [-CtObservedOnly] [-CtMissingOnly] [-ChainCompleteOnly] [-ChainIncompleteOnly] [-ReachableOnly] [-UnreachableOnly] [-HostnameMatchOnly] [-HostnameMismatchOnly] [-SelfSignedOnly] [-CaSignedOnly] [-WeakKeyOnly] [-StrongKeyOnly] [-Sha1SignatureOnly] [-NonSha1SignatureOnly] [-ExpiredOnly] [-NotExpiredOnly] [-NotYetValidOnly] [-AlreadyValidOnly] [-CurrentlyValidOnly] [-CurrentlyInvalidOnly] [-DaysToExpireMin <int>] [-DaysToExpireMax <int>] [-DaysUntilValidMin <int>] [-DaysUntilValidMax <int>] [-AuthenticationProfileEquals <string>] [-KnownCaOnly] [-UnknownCaOnly] [-KnownRootCaOnly] [-UnknownRootCaOnly] [-ServerAuthOnly] [-ClientAuthOnly] [-SecureEmailOnly] [-ReuseCrossServiceOnly] [-ReuseSingleServiceOnly] [-ReuseDistinctServiceCountMin <int>] [-ReuseDistinctServiceCountMax <int>] [-ReuseDistinctPortCountMin <int>] [-ReuseDistinctPortCountMax <int>] [-ReuseCrossPortOnly] [-ReuseSinglePortOnly] [<CommonParameters>]
```

## DESCRIPTION
Scores endpoint certificate exposure, classifies severity, and returns top risk reasons to prioritize remediation.

## EXAMPLES

### EXAMPLE 1
```powershell
Get-DDCertificateInventoryRisk -SinceUtc (Get-Date).ToUniversalTime().AddDays(-30)
```


### EXAMPLE 2
```powershell
Get-DDCertificateInventoryRisk -IncludeHealthy -ExpiringWithinDays 45 -CriticalExpiringWithinDays 10
```


### EXAMPLE 3
```powershell
Get-DDCertificateInventoryRisk -MinimumSeverity High
```


## PARAMETERS

### -AlreadyValidOnly
Only include endpoints with certificates that are already valid (not in future).

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

### -AuthenticationProfileEquals
Optional authentication profile exact-match filter (for example ServerAuthOnly, ClientAuthOnly, MixedOrCustom).

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

### -AuthorityFamilyEquals
Optional leaf authority family exact-match filter (for example DigiCert, LetsEncrypt).

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

### -CaSignedOnly
Only include endpoints using CA-signed certificates.

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

### -ChainCompleteOnly
Only include endpoints with complete certificate chains.

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

### -ChainIncompleteOnly
Only include endpoints with incomplete certificate chains.

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

### -ChainLengthMax
Only include endpoints whose observed chain length is less than or equal to this value.

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

### -ChainLengthMin
Only include endpoints whose observed chain length is greater than or equal to this value.

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

### -ChainSourceContains
Optional chain-source substring filter (for example tls-handshake, aia-download).

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

### -ClientAuthOnly
Only include endpoints whose certificate allows client authentication EKU.

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

### -CriticalExpiringWithinDays
Critical threshold window in days for expiring certificates.

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

### -CtMissingOnly
Only include endpoints whose certificates were not observed in CT logs.

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

### -CtObservedOnly
Only include endpoints whose certificates were observed in CT logs.

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

### -CtSourceContains
Optional CT/discovery source substring filter (for example crt.sh, shodan, censys).

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

### -CtTemplateErrorContains
Optional CT template/configuration error substring filter.

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

### -CurrentlyInvalidOnly
Only include endpoints currently outside certificate validity window.

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

### -CurrentlyValidOnly
Only include endpoints currently within certificate validity window.

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

### -DaysToExpireMax
Only include endpoints whose days-to-expire is less than or equal to this value.

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

### -DaysToExpireMin
Only include endpoints whose days-to-expire is greater than or equal to this value.

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

### -DaysUntilValidMax
Only include endpoints whose days-until-valid is less than or equal to this value.

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

### -DaysUntilValidMin
Only include endpoints whose days-until-valid is greater than or equal to this value.

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

### -ExpiredOnly
Only include endpoints with expired certificates.

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

### -ExpiringWithinDays
Warning threshold window in days for expiring certificates.

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

### -HostContains
Optional case-insensitive host substring filter.

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

### -HostnameMatchOnly
Only include endpoints whose certificate matches the requested hostname.

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

### -HostnameMismatchOnly
Only include endpoints whose certificate does not match the requested hostname.

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

### -IncludeHealthy
Include endpoints without detected risk findings.

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

### -IntermediateCountMax
Only include endpoints whose observed intermediate count is less than or equal to this value.

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

### -IntermediateCountMin
Only include endpoints whose observed intermediate count is greater than or equal to this value.

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

### -IssuerContains
Optional case-insensitive issuer/root-issuer substring filter (for example DigiCert, Let's Encrypt, ISRG).

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

### -IssuerContainsAllOf
Optional case-insensitive issuer/root-issuer substring filters where all values must match.

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

### -IssuerContainsAnyOf
Optional case-insensitive issuer/root-issuer substring filters where any value can match.

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

### -KnownCaOnly
Only include endpoints with recognized public CAs as the leaf issuer.

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

### -KnownRootCaOnly
Only include endpoints chaining to recognized public root CAs.

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

### -MaxEndpoints
Maximum endpoint rows returned.

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

### -MinimumSeverity
Optional minimum severity filter (None means no additional score filter).

```yaml
Type: String
Parameter Sets: __AllParameterSets
Aliases: None
Possible values: None, Low, Medium, High, Critical

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -NonSha1SignatureOnly
Only include endpoints not using SHA-1 signatures.

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

### -NotExpiredOnly
Only include endpoints with non-expired certificates.

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

### -NotYetValidOnly
Only include endpoints with certificates that are not yet valid.

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

### -PortEquals
Optional endpoint port exact-match filter (1-65535).

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

### -ReachableOnly
Only include endpoints reachable on the scanned endpoint.

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

### -ReasonAllOf
Optional exact reason filters where all values must match.

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

### -ReasonAnyOf
Optional exact reason filters where any value can match.

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

### -ReasonContains
Optional case-insensitive reason substring filter (for example CertificateExpired, WeakKey, CtNotObserved).

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

### -ReasonCountMax
Optional maximum reason-count filter (0 or greater).

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

### -ReasonCountMin
Optional minimum reason-count filter (0 or greater).

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

### -ReuseCrossPortOnly
Only include endpoints where the same certificate is reused across more than one distinct port.

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

### -ReuseCrossServiceOnly
Only include endpoints where the same certificate is reused across more than one distinct service.

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

### -ReuseDistinctPortCountMax
Optional maximum certificate-reuse distinct-port-count filter (1 or greater).

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

### -ReuseDistinctPortCountMin
Optional minimum certificate-reuse distinct-port-count filter (1 or greater).

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

### -ReuseDistinctServiceCountMax
Optional maximum certificate-reuse distinct-service-count filter (1 or greater).

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

### -ReuseDistinctServiceCountMin
Optional minimum certificate-reuse distinct-service-count filter (1 or greater).

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

### -ReuseEndpointCountMax
Optional maximum certificate-reuse endpoint-count filter (1 or greater).

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

### -ReuseEndpointCountMin
Optional minimum certificate-reuse endpoint-count filter (1 or greater).

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

### -ReuseSinglePortOnly
Only include endpoints where the same certificate is reused within a single distinct port.

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

### -ReuseSingleServiceOnly
Only include endpoints where the same certificate is reused within a single distinct service.

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

### -RiskProfile
Optional risk profile preset (Renewal14d, Renewal30d, FutureNotYetValid, Expired, HighRiskActive).

```yaml
Type: String
Parameter Sets: __AllParameterSets
Aliases: None
Possible values: Renewal14d, Renewal30d, FutureNotYetValid, Expired, HighRiskActive

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -RootAuthorityFamilyEquals
Optional root authority family exact-match filter (for example DigiCert, LetsEncrypt).

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

### -RootIssuerContains
Optional case-insensitive root-issuer substring filter.

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

### -RootIssuerContainsAllOf
Optional case-insensitive root-issuer substring filters where all values must match.

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

### -RootIssuerContainsAnyOf
Optional case-insensitive root-issuer substring filters where any value can match.

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

### -RootThumbprintEquals
Optional root-certificate thumbprint exact-match filter (hex string expected).

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

### -ScoreMax
Optional maximum endpoint risk score filter (0-100).

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

### -ScoreMin
Optional minimum endpoint risk score filter (0-100).

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

### -SecureEmailOnly
Only include endpoints whose certificate allows secure-email EKU.

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

### -SelfSignedOnly
Only include endpoints using self-signed certificates.

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

### -SerialNumberEquals
Optional leaf-certificate serial-number exact-match filter (hex string expected).

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

### -ServerAuthOnly
Only include endpoints whose certificate allows server authentication EKU.

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

### -ServiceEquals
Optional case-insensitive service exact-match filter (for example HTTPS, HTTPS-Alt, Custom TLS).

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

### -Sha1SignatureOnly
Only include endpoints using SHA-1 signatures.

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

### -SinceUtc
Only include snapshots captured since this UTC date/time.

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

### -StrongKeyOnly
Only include endpoints without weak keys.

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

### -ThumbprintEquals
Optional leaf-certificate thumbprint exact-match filter (hex string expected).

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

### -UnknownCaOnly
Only include endpoints with unrecognized/private CAs as the leaf issuer.

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

### -UnknownRootCaOnly
Only include endpoints chaining to unrecognized/private root CAs.

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

### -UnreachableOnly
Only include endpoints that were not reachable on the scanned endpoint.

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

### -WeakKeyOnly
Only include endpoints with weak keys.

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

- `None`

## OUTPUTS

- `DomainDetective.CertificateInventoryRiskSummary`

## RELATED LINKS

- None

---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# Get-DDCertificateInventoryQuery
## SYNOPSIS
Queries persisted certificate inventory snapshots using structured filters.

## SYNTAX
### __AllParameterSets
```powershell
Get-DDCertificateInventoryQuery [-CacheDirectory <string>] [-SinceUtc <DateTime>] [-UntilUtc <DateTime>] [-HostContains <string>] [-SubjectContains <string>] [-SanContains <string>] [-ServiceEquals <string>] [-IssuerContains <string>] [-AuthorityFamilyEquals <string>] [-RootContains <string>] [-RootAuthorityFamilyEquals <string>] [-CtSourceContains <string>] [-CtTemplateErrorContains <string>] [-ChainSourceContains <string>] [-ThumbprintEquals <string>] [-RootThumbprintEquals <string>] [-SerialNumberEquals <string>] [-KnownCaOnly] [-UnknownCaOnly] [-KnownRootCaOnly] [-UnknownRootCaOnly] [-ValidOnly] [-InvalidOnly] [-ExpiredOnly] [-ChainIncompleteOnly] [-ChainCompleteOnly] [-HostnameMismatchOnly] [-HostnameMatchOnly] [-SelfSignedOnly] [-NotSelfSignedOnly] [-UnreachableOnly] [-ReachableOnly] [-CtOnly] [-CtMissingOnly] [-ServerAuthOnly] [-NoServerAuthOnly] [-ClientAuthOnly] [-NoClientAuthOnly] [-SecureEmailOnly] [-NoSecureEmailOnly] [-WeakKeyOnly] [-Sha1SignatureOnly] [-NotYetValidOnly] [-ExpiringWithinDays <Int32>] [-AuthenticationProfileEquals <string>] [-LatestOnly] [-MaxResults <int>] [<CommonParameters>]
```

## DESCRIPTION
Returns matched inventory entries with snapshot capture times and counters for scanned and matched records.

## EXAMPLES

### EXAMPLE 1
```powershell
Get-DDCertificateInventoryQuery -KnownCaOnly -ExpiringWithinDays 30 -MaxResults 1000
```


### EXAMPLE 2
```powershell
Get-DDCertificateInventoryQuery -ClientAuthOnly -ChainIncompleteOnly -HostnameMismatchOnly
```


### EXAMPLE 3
```powershell
Get-DDCertificateInventoryQuery -AuthorityFamilyEquals LetsEncrypt -KnownRootCaOnly -CtSourceContains shodan
```


### EXAMPLE 4
```powershell
Get-DDCertificateInventoryQuery -InvalidOnly -ReachableOnly
```


### EXAMPLE 5
```powershell
Get-DDCertificateInventoryQuery -LatestOnly -HostContains \"example.com\"
```


## PARAMETERS

### -AuthenticationProfileEquals
Authentication profile exact-match filter.

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
Leaf authority family exact-match filter.

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

### -ChainCompleteOnly
Only include entries with complete chains.

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
Only include entries with incomplete chains.

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

### -ChainSourceContains
Certificate chain source substring filter.

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
Only include certificates allowing client authentication EKU.

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

### -CtMissingOnly
Only include certificates not observed in CT logs.

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

### -CtOnly
Only include certificates observed in CT logs.

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
CT source substring filter.

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
CT template/configuration error substring filter.

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

### -ExpiredOnly
Only include expired certificates.

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
Only include certificates expiring within this many days.

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
Host substring filter.

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
Only include entries where hostname validation succeeded.

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
Only include entries where hostname validation failed.

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

### -InvalidOnly
Only include entries with invalid certificates.

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

### -IssuerContains
Issuer substring filter.

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

### -KnownCaOnly
Only include certificates from recognized public CAs.

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
Only include certificates chaining to recognized public root CAs.

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

### -LatestOnly
Only evaluate the latest observed entry per endpoint (host+port) in the selected snapshot window.

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

### -MaxResults
Maximum number of results returned.

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

### -NoClientAuthOnly
Only include certificates that do not allow client authentication EKU.

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

### -NoSecureEmailOnly
Only include certificates that do not allow secure email EKU.

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

### -NoServerAuthOnly
Only include certificates that do not allow server authentication EKU.

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

### -NotSelfSignedOnly
Only include certificates that are not self-signed.

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
Only include certificates that are not yet valid.

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

### -ReachableOnly
Only include reachable endpoints.

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

### -RootAuthorityFamilyEquals
Root authority family exact-match filter.

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

### -RootContains
Root issuer/subject substring filter.

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

### -RootThumbprintEquals
Root certificate thumbprint exact-match filter.

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

### -SanContains
Certificate SAN substring filter.

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

### -SecureEmailOnly
Only include certificates allowing secure email EKU.

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
Only include self-signed certificates.

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
Leaf certificate serial-number exact-match filter (hex string expected).

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
Only include certificates allowing server authentication EKU.

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
Service equality filter (for example HTTPS, HTTPS-Alt, Custom TLS).

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
Only include certificates signed with SHA-1.

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
Type: DateTime
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SubjectContains
Certificate subject substring filter.

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

### -ThumbprintEquals
Leaf certificate thumbprint exact-match filter.

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
Only include certificates from unrecognized or private CAs.

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
Only include certificates chaining to unrecognized or private root CAs.

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
Only include unreachable endpoints.

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

### -UntilUtc
Only include snapshots captured up to this UTC date/time.

```yaml
Type: DateTime
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ValidOnly
Only include entries with valid certificates.

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
Only include certificates that use weak keys.

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

- `DomainDetective.CertificateInventoryQueryResult`

## RELATED LINKS

- None

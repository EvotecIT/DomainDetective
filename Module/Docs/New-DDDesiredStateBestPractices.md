---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# New-DDDesiredStateBestPractices
## SYNOPSIS
Creates best-practice settings for Desired State evaluation.

## SYNTAX
### __AllParameterSets
```powershell
New-DDDesiredStateBestPractices [-Checks <HealthCheckType[]>] [-IncludeActiveMailProbes] [<CommonParameters>]
```

## DESCRIPTION
The returned object can be applied in New-DDDesiredState to override the best-practice check set.

## EXAMPLES

### EXAMPLE 1
```powershell
PS> New-DDDesiredStateBestPractices -IncludeActiveMailProbes
```

Adds SMTP/IMAP/POP probes to the recommended best-practice checks.

### EXAMPLE 2
```powershell
PS> New-DDDesiredStateBestPractices -Checks DMARC,SPF,DKIM,MTASTS,TLSRPT
```

Uses only the specified checks when DesiredStateMode is BestPracticesForUnspecified.

## PARAMETERS

### -Checks
Optional list of checks to use as the best-practice baseline.

```yaml
Type: HealthCheckType[]
Parameter Sets: __AllParameterSets
Aliases: None
Possible values: DMARC, SPF, DKIM, MX, REVERSEDNS, FCRDNS, CAA, NS, DELEGATION, ZONETRANSFER, DANE, SMIMEA, DNSBL, DNSSEC, MTASTS, TLSRPT, BIMI, AUTODISCOVER, CERT, SECURITYTXT, ROBOTS, SOA, OPENRELAY, OPENRESOLVER, STARTTLS, SMTPTLS, IMAPTLS, POP3TLS, SMTPBANNER, SMTPAUTH, HTTP, HPKP, CONTACT, MESSAGEHEADER, ARC, DANGLINGCNAME, TTL, PORTAVAILABILITY, PORTSCAN, SNMP, IPNEIGHBOR, IPENRICHMENT, RPKI, DNSTUNNELING, TYPOSQUATTING, THREATINTEL, THREATFEED, WILDCARDDNS, EDNSSUPPORT, DNSHEALTH, MAILLATENCY, FLATTENINGSERVICE, RDAP, DIRECTORYEXPOSURE, NTP, WEBSITE, WHOIS, APEXADDRESS, SPFFLATTENED, MAILCLASSIFICATION, SUBDOMAINS, DNSINVENTORY, DNSTRACE, CTTIMELINE, DNSPROPAGATION, DNSAMPLIFICATION, DNSOVERTLS, IDENTITYPROVIDER, MICROSOFT365, SITEMAP, AGENTREADINESS

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -IncludeActiveMailProbes
Include SMTP/IMAP/POP active probes in the best-practice set.

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

- `DomainDetective.DesiredState.DesiredStateBestPracticeSettings`

## RELATED LINKS

- None

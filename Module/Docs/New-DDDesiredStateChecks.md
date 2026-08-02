---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# New-DDDesiredStateChecks
## SYNOPSIS
Creates a desired state fragment that controls which checks are executed.

## SYNTAX
### __AllParameterSets
```powershell
New-DDDesiredStateChecks -Checks <HealthCheckType[]> [<CommonParameters>]
```

## DESCRIPTION
Use this to enable/disable specific HealthCheckType modules for the effective profile.

## EXAMPLES

### EXAMPLE 1
```powershell
PS> New-DDDesiredStateChecks -Checks DMARC,SPF,DKIM
```


## PARAMETERS

### -Checks
Checks to execute for the desired state profile.

```yaml
Type: HealthCheckType[]
Parameter Sets: __AllParameterSets
Aliases: None
Possible values: DMARC, SPF, DKIM, MX, REVERSEDNS, FCRDNS, CAA, NS, DELEGATION, ZONETRANSFER, DANE, SMIMEA, DNSBL, DNSSEC, MTASTS, TLSRPT, BIMI, AUTODISCOVER, CERT, SECURITYTXT, ROBOTS, SOA, OPENRELAY, OPENRESOLVER, STARTTLS, SMTPTLS, IMAPTLS, POP3TLS, SMTPBANNER, SMTPAUTH, HTTP, HPKP, CONTACT, MESSAGEHEADER, ARC, DANGLINGCNAME, TTL, PORTAVAILABILITY, PORTSCAN, SNMP, IPNEIGHBOR, IPENRICHMENT, RPKI, DNSTUNNELING, TYPOSQUATTING, THREATINTEL, THREATFEED, WILDCARDDNS, EDNSSUPPORT, DNSHEALTH, MAILLATENCY, FLATTENINGSERVICE, RDAP, DIRECTORYEXPOSURE, NTP, WEBSITE, WHOIS, APEXADDRESS, SPFFLATTENED, MAILCLASSIFICATION, SUBDOMAINS, DNSINVENTORY, DNSTRACE, CTTIMELINE, DNSPROPAGATION, DNSAMPLIFICATION, DNSOVERTLS, IDENTITYPROVIDER, MICROSOFT365, SITEMAP, AGENTREADINESS

Required: True
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

- `DomainDetective.DesiredState.DesiredStateProfile`

## RELATED LINKS

- None

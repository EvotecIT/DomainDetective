# Desired State (custom baseline)

DomainDetective can detect security posture and provide best-practice recommendations. Some organizations also need a **custom baseline** to detect **non-conformance / drift** against their own standards (for example: hosted DMARC reporting services).

This document introduces a first-pass Desired State Configuration (DSC-like) layer:

- A JSON configuration file describing your baseline and per-domain/per-classification overrides.
- A PowerShell entry point that runs checks and evaluates conformance.

## PowerShell usage

### Test a domain against a JSON baseline

```powershell
Test-DDDesiredState -DomainName example.com -DesiredStatePath .\desired-state.json
```

### Build a baseline in PowerShell (DSL) and test without JSON

`New-DDDesiredState` supports a PowerShell DSL (script block) that returns desired-state fragments (profiles/overrides).

```powershell
$cfg = New-DDDesiredState {
    New-DDDesiredStateChecks -Checks DMARC,SPF,DKIM,MTASTS,TLSRPT

    New-DDDesiredStateDmarc -Enabled $true `
        -AllowedPolicies reject,quarantine `
        -RequireRua $true `
        -AllowedReportDomainSuffixes dmarc.powermarc.com `
        -RequireExternalReportAuthorization $true

    New-DDDesiredStateSpf -Enabled $true `
        -AllowedAllMechanisms '-all', '~all' `
        -MaxDnsLookups 10 `
        -RequiredIncludeDomains spf.protection.outlook.com `
        -DisallowPtr $true

    New-DDDesiredStateDkim -Enabled $true `
        -RequiredSelectors selector1, selector2 `
        -MinKeyBits 2048

    New-DDDesiredStateMtasts -Enabled $true `
        -RequireRecord $true `
        -RequireEnforce $true `
        -MinMaxAge 86400

    New-DDDesiredStateTlsRpt -Enabled $true `
        -RequireRecord $true `
        -RequireValidPolicy $true `
        -AllowedReportDomainSuffixes tlsrpt.vendor.example

    New-DDDesiredStateOverride -DomainPatterns '*.example.com' -Classifications Parked {
        New-DDDesiredStateDmarc -RequireRua $false
        New-DDDesiredStateSpf -RequireDenyAll $true
    }

    # Optional: suppress or change severity for specific assessment codes
    New-DDDesiredStateAssessmentPolicy -SuppressCodes DMARC.Alignment.Mismatch `
        -SeverityOverrides @{
            'DesiredState.DMARC.RUA.Domain.NotAllowed' = 'Warning'
        }
}

Test-DDDesiredState -DomainName example.com -Configuration $cfg
```

### Build a baseline using typed .NET classes (no DSL)

All desired state types are regular .NET classes, so you can create and edit them directly in PowerShell.

```powershell
$cfg = New-DDDesiredState

$cfg.Defaults.Checks = [DomainDetective.Definitions.HealthCheckType[]]@(
    [DomainDetective.Definitions.HealthCheckType]::DMARC,
    [DomainDetective.Definitions.HealthCheckType]::SPF,
    [DomainDetective.Definitions.HealthCheckType]::DKIM
)

$cfg.Defaults.Dmarc = [DomainDetective.DesiredState.DesiredStateDmarcPolicy]::new()
$cfg.Defaults.Dmarc.AllowedPolicies = @('reject', 'quarantine')
$cfg.Defaults.Dmarc.RequireRua = $true
$cfg.Defaults.Dmarc.AllowedReportDomainSuffixes = @('dmarc.powermarc.com')
$cfg.Defaults.Dmarc.RequireExternalReportAuthorization = $true

$cfg.Defaults.Spf = [DomainDetective.DesiredState.DesiredStateSpfPolicy]::new()
$cfg.Defaults.Spf.AllowedAllMechanisms = @('-all', '~all')
$cfg.Defaults.Spf.MaxDnsLookups = 10
$cfg.Defaults.Spf.RequiredIncludeDomains = @('spf.protection.outlook.com')
$cfg.Defaults.Spf.DisallowPtr = $true

Test-DDDesiredState -DomainName example.com -Configuration $cfg
```

### Load JSON, override values in memory, then test

```powershell
$cfg = New-DDDesiredState -LoadPath .\desired-state.json

if ($cfg.Defaults.Dmarc -eq $null) {
    $cfg.Defaults.Dmarc = [DomainDetective.DesiredState.DesiredStateDmarcPolicy]::new()
}
$cfg.Defaults.Dmarc.AllowedReportDomainSuffixes = @('dmarc.powermarc.com')

Test-DDDesiredState -DomainName example.com -Configuration $cfg
```

### Export configuration to JSON

There is no dedicated export cmdlet yet; you can serialize the in-memory configuration using the same serializer settings as DomainDetective:

```powershell
$json = [System.Text.Json.JsonSerializer]::Serialize($cfg, [DomainDetective.Helpers.JsonOptions]::Default)
Set-Content -Path .\desired-state.json -Value $json -Encoding UTF8
```

### Notes on mail classification overrides

- If your configuration contains `overrides.match.classifications`, `Test-DDDesiredState` runs mail classification automatically to choose the correct desired state.
- To skip classification even when overrides include classifications, use `-NoClassification`:

```powershell
Test-DDDesiredState -DomainName example.com -DesiredStatePath .\desired-state.json -NoClassification
```

## Configuration file

Add a `$schema` field for editor IntelliSense:

```json
{
  "$schema": "./Docs/Schemas/domain-detective.desired-state.schema.json",
  "version": 1,
  "defaults": {
    "checks": [
      "DMARC",
      "SPF",
      "DKIM",
      "MTASTS",
      "TLSRPT",
      "BIMI",
      "AUTODISCOVER",
      "SECURITYTXT",
      "ROBOTS",
      "MX",
      "REVERSEDNS",
      "FCRDNS",
      "DNSBL",
      "NS",
      "DNSHEALTH",
      "APEXADDRESS",
      "RPKI",
      "EDNSSUPPORT",
      "DNSOVERTLS",
      "FLATTENINGSERVICE",
      "DANGLINGCNAME",
      "CAA",
      "DNSSEC",
      "SOA",
      "DANE",
      "DELEGATION",
      "ZONETRANSFER",
      "WILDCARDDNS",
      "TTL"
    ],
    "assessmentPolicy": {
      "suppressCodes": [ "DMARC.Alignment.Mismatch" ]
    },
    "dmarc": {
      "allowedPolicies": [ "reject", "quarantine" ],
      "allowedSubdomainPolicies": [ "reject", "quarantine" ],
      "allowedAspfAlignments": [ "r", "s" ],
      "allowedAdkimAlignments": [ "r", "s" ],
      "requireRua": true,
      "allowedReportDomainSuffixes": [ "dmarc.powermarc.com" ],
      "requireExternalReportAuthorization": true
    },
    "spf": {
      "allowedAllMechanisms": [ "-all", "~all" ],
      "maxDnsLookups": 10,
      "requiredIncludeDomains": [ "spf.protection.outlook.com" ],
      "disallowPtr": true
    },
    "dkim": {
      "requiredSelectors": [ "selector1", "selector2" ],
      "minKeyBits": 2048,
      "allowedCnameTargetSuffixes": [ "sendgrid.net" ]
    },
    "mtasts": {
      "requireRecord": true,
      "requireEnforce": true,
      "minMaxAge": 86400
    },
    "tlsrpt": {
      "requireRecord": true,
      "requireValidPolicy": true,
      "allowedReportDomainSuffixes": [ "tlsrpt.vendor.example" ]
    },
    "bimi": {
      "requireValidLocation": true,
      "allowedLocationHostSuffixes": [ "cdn.vendor.example" ],
      "skipIndicatorDownload": true
    },
    "mx": {
      "requireRecord": true,
      "disallowNullMx": true,
      "allowedHostSuffixes": [ "protection.outlook.com" ]
    },
    "autodiscover": {
      "requireAutodiscoverCname": true,
      "allowedAutodiscoverCnameTargetSuffixes": [ "outlook.com", "office365.com" ],
      "requireAnyValidEndpoint": false
    },
    "reverseDns": {
      "requirePtrPresent": true,
      "allowedPtrSuffixes": [ "protection.outlook.com" ],
      "requireForwardConfirmed": true
    },
    "fcrDns": {
      "requireAllForwardConfirmed": true
    },
    "dnsbl": {
      "disallowListings": true,
      "includeQueryKinds": [ "IpAddressV4", "IpAddressV6" ],
      "includeIpSources": [ "MxA", "MxAAAA" ]
    },
    "ns": {
      "requireAtLeastTwo": true,
      "requireDiversity": false
    },
    "dnsHealth": {
      "requireServersResponsive": true,
      "requireSoaSerialConsistent": true,
      "requireApexAddressesConsistent": true
    },
    "apexAddress": {
      "disallowPrivateAddresses": true,
      "disallowLoopbackAddresses": true,
      "disallowLinkLocalAddresses": true,
      "disallowMulticastAddresses": true,
      "disallowDocumentationAddresses": true,
      "disallowUniqueLocalV6Addresses": true
    },
    "rpki": {
      "disallowInvalid": true,
      "treatQueryFailuresAsDrift": false
    },
    "ednsSupport": {
      "requireAllServersSupported": true,
      "maxUdpPayloadSize": 1232,
      "requireCookieSupport": false
    },
    "dnsOverTls": {
      "requireAnySupported": false,
      "requireCertificateValid": true,
      "requireHostnameMatch": true
    },
    "flatteningService": {
      "allowedTargetSuffixes": [ "cloudflare.net" ]
    },
    "danglingCname": {
      "disallowDangling": true,
      "disallowUnclaimedService": true
    },
    "caa": {
      "requireRecord": true,
      "requireValid": true,
      "allowedCertificateIssuers": [ "letsencrypt.org" ]
    },
    "dnssec": {
      "requireChainValid": true,
      "minRrsigDaysRemaining": 7
    },
    "soa": {
      "requireRecord": true,
      "requireSerialFormat": false,
      "minRefresh": 1800,
      "maxRefresh": 86400
    },
    "dane": {
      "requireRecord": false,
      "requireValidRecords": true,
      "requiredServices": [ "SMTP" ],
      "requireRecommendedForSmtp": true
    },
    "delegation": {
      "requireMatchesParent": true,
      "requireGlueComplete": true,
      "requireGlueConsistent": true
    },
    "zoneTransfer": {
      "disallowUnauthenticatedAxfr": true
    },
    "wildcardDns": {
      "expectedCatchAll": false
    },
    "ttl": {
      "minASeconds": 300,
      "maxASeconds": 86400,
      "minDmarcTxtSeconds": 3600,
      "requireAUniformAcrossNs": true
    },
    "securityTxt": {
      "requireRecord": false,
      "requireValid": false,
      "disallowFallback": false,
      "requireContactEmail": false
    },
    "robots": {
      "requireRecord": false,
      "disallowFallback": false,
      "requireAiBotRules": false,
      "requireSitemap": false
    }
  },
  "overrides": [
    {
      "match": {
        "domainPatterns": [ "*.example.com" ],
        "classifications": [ "Parked" ]
      },
      "profile": {
        "spf": { "requireDenyAll": true },
        "dmarc": { "requireRua": false },
        "apexAddress": { "disallowAnyAddress": true }
      }
    }
  ]
}
```

### Notes

- `checks` controls which `HealthCheckType` modules are executed for the profile.
- `assessmentPolicy` can suppress or re-severity existing built-in assessment codes (useful when your org intentionally deviates from generic best practices).
- `Conforms` is calculated from the remaining (post-policy) assessments across all executed checks plus any `DesiredState.*` drift findings.
- `dmarc.allowedReportDomainSuffixes` enables vendor-specific baselining (for example: require `rua=` to use your hosted DMARC provider domain suffix).
- `overrides.match.classifications` uses DomainDetective mail classification (Sending/Receiving/Parked) to pick different desired states per domain role.

## Current scope

The initial desired state evaluator covers:

- DMARC: required record, policy allow-list, `rua` required, report-domain suffix allow-list, and external report authorization checks.
- SPF: required record, `all` mechanism allow-list, DNS lookup threshold, and "deny-all" requirement.
- DKIM: required selector allow-list, minimum key size, and CNAME target suffix allow-list (vendor-hosted DKIM).
- MTA-STS: required record, enforce-mode requirement, max_age minimum, and policy MX alignment requirement.
- TLSRPT: required record, valid-policy requirement, `rua` requirement, and report-domain suffix allow-list.
- BIMI: optional record requirement, indicator-decline detection, location validity, and location/authority host suffix allow-lists (vendor-hosted BIMI/VMC).
- MX: required record, null-MX (RFC 7505) required/disallowed, host suffix allow-list, backup-server and integrity checks.
- NS: required record, minimum record count, duplicates/CNAME/address checks, and optional diversity constraints.
- CAA: required record, valid-policy requirement, issuer allow-lists, and optional iodef endpoint constraints.
- DNSSEC: valid-chain requirement and optional RRSIG-expiration thresholds.
- SOA: required record plus optional serial-format and timing range thresholds.
- DANE: required record (optionally by service), validity requirement, and optional "recommended config" requirements.
- REVERSEDNS: optional PTR presence/expected-host enforcement, PTR suffix allow-list, and optional forward-confirmation requirements.
- FCRDNS: optional forward-confirmation requirements for PTR hostnames.
- DNSBL: optional "no listings" enforcement with ignore lists and query-kind/IP-source filters.
- DANGLINGCNAME: optional enforcement against dangling CNAMEs and unclaimed-service takeovers.
- DNSHEALTH: optional enforcement of authoritative SOA serial and apex A/AAAA consistency plus server responsiveness.
- APEXADDRESS: optional apex A/AAAA requirements, address hygiene constraints (private/loopback/etc.), subnet diversity, and PTR/FCrDNS enforcement.
- RPKI: optional "no invalid origins" enforcement with ignore lists and optional handling for query failures.
- EDNSSUPPORT: optional enforcement of EDNS support (version 0), UDP payload thresholds, and DNS Cookies support.
- DNSOVERTLS: optional enforcement of DoT support on authoritative servers with certificate validity/hostname constraints.
- FLATTENINGSERVICE: optional enforcement of apex CNAME presence/absence, flattening-service detection, and vendor target suffix allow-list.
- DELEGATION: require parent/child NS match and glue completeness/consistency.
- ZONETRANSFER: disallow unauthenticated AXFR on authoritative name servers.
- WILDCARDDNS: enforce whether wildcard (catch-all) DNS is expected or disallowed.
- TTL: customizable TTL thresholds and uniformity requirements across authoritative name servers.
- AUTODISCOVER: optional requirements for SRV/CNAME records, target suffix allow-lists, and endpoint validation/host allow-lists.
- SECURITYTXT: optional requirements for presence/validity, contact email constraints, and HTTPS fallback handling.
- ROBOTS: optional requirements for presence, HTTPS fallback handling, AI bot directive presence, and sitemap declaration.

The configuration model is intended to be extended to additional checks over time while preserving schema compatibility (versioned config + typed keys).

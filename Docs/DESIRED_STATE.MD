# Desired State (custom baseline)

DomainDetective can detect security posture and provide best-practice recommendations. Some organizations also need a **custom baseline** to detect **non-conformance / drift** against their own standards (for example: hosted DMARC reporting services).

This document introduces a first-pass Desired State Configuration (DSC-like) layer:

- A JSON configuration file describing your baseline and per-domain/per-classification overrides.
- A PowerShell entry point that runs checks and evaluates conformance.

## PowerShell usage

```powershell
Test-DDDesiredState -DomainName example.com -DesiredStatePath .\desired-state.json
```

## Configuration file

Add a `$schema` field for editor IntelliSense:

```json
{
  "$schema": "./Docs/Schemas/domain-detective.desired-state.schema.json",
  "version": 1,
  "defaults": {
    "checks": [ "DMARC", "SPF", "DKIM", "MTASTS", "TLSRPT", "BIMI" ],
    "assessmentPolicy": {
      "suppressCodes": [
        "DMARC.Alignment.Mismatch"
      ]
    },
    "dmarc": {
      "allowedPolicies": [ "reject", "quarantine" ],
      "requireRua": true,
      "allowedReportDomainSuffixes": [ "dmarc.powermarc.com" ],
      "requireExternalReportAuthorization": true
    },
    "spf": {
      "allowedAllMechanisms": [ "-all", "~all" ],
      "maxDnsLookups": 10
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
        "dmarc": { "requireRua": false }
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

The configuration model is intended to be extended to additional checks over time while preserving schema compatibility (versioned config + typed keys).

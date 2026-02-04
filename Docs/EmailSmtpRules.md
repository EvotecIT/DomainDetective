# SMTP Rules JSON

This file lets you override SMTP probing behavior by domain or MX host.

## Schema

Top-level keys:
- `byDomain`: domain -> policy
- `byMx`: full MX host -> policy
- `byMxSuffix`: MX host suffix -> policy

Policy keys:
- `disableCatchAll` (bool)
- `smtpTimeoutSeconds` (int)
- `smtpPortOverride` (int)

All keys are case-insensitive. Domains and MX hosts are normalized (trimmed and lowercased). Suffix entries should include a leading dot.

## Example

```json
{
  "byDomain": {
    "example.com": { "disableCatchAll": true, "smtpTimeoutSeconds": 30 }
  },
  "byMxSuffix": {
    ".antispamcloud.com": { "disableCatchAll": true, "smtpTimeoutSeconds": 45 }
  }
}
```

## Notes

- The highest `smtpTimeoutSeconds` value wins when multiple rules apply.
- Built-in rules are used when `UseBuiltinSmtpRules` is true and no custom path is provided.

## CLI example

```bash
ddcli ValidateEmail user@example.com --smtp --catch-all --smtp-rules ./smtp-rules.json
ddcli ValidateEmail user@example.com --smtp --smtp-rules ./smtp-rules.json --no-builtin-smtp-rules
```

## PowerShell example

```powershell
Test-DDEmailAddress -EmailAddress "user@example.com" -SmtpProbe -SmtpRulesPath "./smtp-rules.json"
Test-DDEmailAddress -EmailAddress "user@example.com" -SmtpProbe -SmtpRulesPath "./smtp-rules.json" -DisableBuiltinSmtpRules
```

## Proton provider web check

Proton account checks require a valid authenticated session.
Provide the `AUTH-<uid>` cookie value and the `x-pm-uid` header value from an active Proton session.
If the values are missing or invalid, DomainDetective falls back to SMTP probing.

PowerShell example:
```powershell
Test-DDEmailAddress -EmailAddress "user@proton.me" -SmtpProbe -EnableProviderWebChecks -ProtonAuthCookie "AUTH-<uid>=<value>" -ProtonUid "<uid>"
```

CLI example:
```bash
ddcli ValidateEmail user@proton.me --smtp --provider-web --proton-auth "AUTH-<uid>=<value>" --proton-uid "<uid>"
```

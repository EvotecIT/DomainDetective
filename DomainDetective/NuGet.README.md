# DomainDetective

`DomainDetective` is the base analysis package for domain, DNS, email, web, and certificate security checks.

Use this package when you want the core analyzers, models, and orchestration surface such as `DomainHealthCheck`.

Optional dependency-heavy features are split into companion packages:

- `DomainDetective.Pgp` for PGP-backed `security.txt` verification
- `DomainDetective.Visual` for Playwright/ImageSharp visual typosquatting checks
- `DomainDetective.CtSql` for the future CT SQL extraction path; future crt.sh SQL code should use `identities(c.certificate)` full-text search rather than the superseded `certificate_identity` table

Example:

```csharp
using DomainDetective;

var healthCheck = new DomainHealthCheck();
await healthCheck.Verify("example.com");
```

# DomainDetective.Pgp

`DomainDetective.Pgp` adds optional PGP-backed `security.txt` signature verification to the base `DomainDetective` package.

Register it once during startup:

```csharp
using DomainDetective.Pgp;

DomainDetectivePgpRegistration.Register();
```

Without this package, `security.txt` files still parse, but detached clear-signature verification is skipped.

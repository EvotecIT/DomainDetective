# DomainDetective.CtSql

`DomainDetective.CtSql` is the prepared package shell for the future Certificate Transparency SQL extraction.

The current PostgreSQL-backed CT implementation still lives in the base `DomainDetective` package. This package exists so the eventual move can happen with a stable package identity and registration surface.

This package does not activate a built-in provider yet. If you call `DomainDetectiveCtSqlRegistration.Register(...)` in this release, pass your own exact-host metadata provider delegate; the bundled implementation will move here in a future release.

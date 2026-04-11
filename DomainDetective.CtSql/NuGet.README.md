# DomainDetective.CtSql

`DomainDetective.CtSql` is the prepared package shell for the future Certificate Transparency SQL extraction.

The current PostgreSQL-backed CT implementation still lives in the base `DomainDetective` package. This package exists so the eventual move can happen with a stable package identity and registration surface.

This package does not activate a built-in provider yet. If you call `DomainDetectiveCtSqlRegistration.Register(...)` in this release, pass your own exact-host metadata provider delegate; the bundled implementation will move here in a future release.

Future crt.sh PostgreSQL implementation should use crt.sh SQL FTS on the `certificate` table:

```sql
WHERE identities(c.certificate) @@ plainto_tsquery('simple', @host)
```

Do not build new code against `certificate_identity`; crt.sh reports that table is superseded by the full-text search index on `certificate`. Treat public crt.sh PostgreSQL as best-effort historical/backfill infrastructure and apply strict timeouts/cooldowns.

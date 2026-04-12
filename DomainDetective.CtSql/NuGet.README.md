# DomainDetective.CtSql

`DomainDetective.CtSql` contains the optional crt.sh PostgreSQL Certificate Transparency provider.

Use it when you want CT queries or metadata enrichment from the public crt.sh PostgreSQL replica without adding PostgreSQL dependencies to the base `DomainDetective` package.

```csharp
using DomainDetective;
using DomainDetective.CtSql;

DomainDetectiveCtSqlRegistration.Register();

var options = new CertificateInventoryCaptureOptions {
    EnableCrtShPostgreSqlMetadataFallback = true,
    CrtShPostgreSqlCommandTimeoutSeconds = 15,
    CrtShPostgreSqlMaximumConcurrentRequests = 2
};
```

For service-style CT ingestion, instantiate the provider directly through the shared CT abstraction:

```csharp
ICtCertificateTransparencyProvider provider = new CrtShPostgreSqlCertificateTransparencyProvider(options);

CtCertificateQueryResult latest = await provider.QueryAsync(
    CtCertificateQuery.ForExactHostLatest("www.example.com"));

CtCertificateQueryResult history = await provider.QueryAsync(
    CtCertificateQuery.ForExactHostHistory("www.example.com"));

CtCertificateQueryResult expansion = await provider.QueryAsync(
    CtCertificateQuery.ForDomainExpansion("example.com"));
```

The provider uses DbaClientX for typed PostgreSQL query execution and keeps the supported crt.sh full-text search path (`identities(c.certificate)`) rather than the superseded `certificate_identity` table.

The crt.sh PostgreSQL implementation uses crt.sh SQL FTS on the `certificate` table:

```sql
WHERE identities(c.certificate) @@ plainto_tsquery('simple', @host)
```

Do not build new code against `certificate_identity`; crt.sh reports that table is superseded by the full-text search index on `certificate`. Treat public crt.sh PostgreSQL as best-effort historical/backfill infrastructure and apply strict timeouts/cooldowns.

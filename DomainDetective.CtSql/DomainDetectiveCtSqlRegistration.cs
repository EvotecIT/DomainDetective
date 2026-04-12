using System;
using System.Threading;
using System.Threading.Tasks;
using DomainDetective;

namespace DomainDetective.CtSql;

/// <summary>
/// Registers the optional CT SQL provider for DomainDetective certificate inventory enrichment.
/// </summary>
public static class DomainDetectiveCtSqlRegistration
{
    /// <summary>
    /// Registers the bundled DbaClientX-backed crt.sh PostgreSQL provider.
    /// </summary>
    /// <remarks>Call this once during application startup before running CT metadata capture that enables <see cref="CertificateInventoryCaptureOptions.EnableCrtShPostgreSqlMetadataFallback"/>.</remarks>
    public static void Register()
    {
        DomainDetectiveOptionalFeatures.RegisterCtSqlMetadataProvider(new CrtShPostgreSqlMetadataProvider());
    }

    /// <summary>
    /// Registers a caller-supplied CT SQL exact metadata provider, replacing any provider already registered.
    /// </summary>
    /// <param name="exactMetadataProvider">Provider invoked for exact-host CT metadata lookups when a host application needs to override the bundled provider.</param>
    public static void Register(
        Func<string, CertificateInventoryCaptureOptions, InternalLogger?, CancellationToken, Task<SubdomainDiscoveryEntry?>> exactMetadataProvider)
    {
        DomainDetectiveOptionalFeatures.RegisterCtSqlExactMetadataProvider(exactMetadataProvider);
    }
}

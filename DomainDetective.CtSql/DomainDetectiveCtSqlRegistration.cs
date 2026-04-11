using System;
using System.Threading;
using System.Threading.Tasks;
using DomainDetective;

namespace DomainDetective.CtSql;

/// <summary>
/// Prepared registration entry point for future CT SQL extraction.
/// </summary>
public static class DomainDetectiveCtSqlRegistration
{
    /// <summary>
    /// Registers a caller-supplied CT SQL exact metadata provider, replacing any provider already registered.
    /// </summary>
    /// <param name="exactMetadataProvider">Provider invoked for exact-host CT metadata lookups until the CtSql implementation moves into this package.</param>
    public static void Register(
        Func<string, CertificateInventoryCaptureOptions, InternalLogger?, CancellationToken, Task<SubdomainDiscoveryEntry?>> exactMetadataProvider)
    {
        DomainDetectiveOptionalFeatures.RegisterCtSqlExactMetadataProvider(exactMetadataProvider);
    }
}

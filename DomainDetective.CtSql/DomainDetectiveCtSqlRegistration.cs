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
    public static void Register(
        Func<string, CertificateInventoryCaptureOptions, InternalLogger?, CancellationToken, Task<SubdomainDiscoveryEntry?>> exactMetadataProvider)
    {
        DomainDetectiveOptionalFeatures.RegisterCtSqlExactMetadataProvider(exactMetadataProvider);
    }
}

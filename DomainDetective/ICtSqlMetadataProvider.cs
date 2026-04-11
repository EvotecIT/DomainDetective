using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

internal interface ICtSqlMetadataProvider
{
    Task<SubdomainDiscoveryEntry?> QueryExactMetadataAsync(
        string hostName,
        CertificateInventoryCaptureOptions options,
        InternalLogger? logger,
        ISet<string>? targetedThumbprints,
        CancellationToken cancellationToken);

    Task<IReadOnlyDictionary<string, SubdomainDiscoveryEntry>> QueryDomainMetadataAsync(
        string domain,
        IReadOnlyCollection<string> hostNames,
        CertificateInventoryCaptureOptions options,
        InternalLogger? logger,
        ISet<string>? targetedThumbprints,
        CancellationToken cancellationToken);
}

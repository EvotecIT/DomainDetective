using System;

namespace DomainDetective;

/// <summary>
/// Describes an estimated certificate transparency workload for provider planning.
/// </summary>
public sealed class CtIngestionWorkloadRequest
{
    /// <summary>Number of root domains included in the workload.</summary>
    public int DomainCount { get; init; }

    /// <summary>Number of exact hosts or assets included in the workload.</summary>
    public int HostCount { get; init; }

    /// <summary>Operations requested by the workload.</summary>
    public CtIngestionOperation Operations { get; init; }

    /// <summary>Whether the workload requires full DER or PEM certificate material.</summary>
    public bool RequireFullCertificate { get; init; } = true;

    /// <summary>Estimated provider requests per domain-level operation.</summary>
    public int RequestsPerDomain { get; init; } = 1;

    /// <summary>Estimated provider requests per exact-host operation.</summary>
    public int RequestsPerHost { get; init; } = 1;

    /// <summary>Estimated follow-up full certificate hydration requests per returned certificate.</summary>
    public int HydrationRequestsPerCertificate { get; init; }

    /// <summary>Estimated number of certificate rows that will need hydration.</summary>
    public int EstimatedCertificatesToHydrate { get; init; }

    /// <summary>Returns a normalized copy of this workload request.</summary>
    public CtIngestionWorkloadRequest Normalize()
    {
        return new CtIngestionWorkloadRequest
        {
            DomainCount = Math.Max(0, DomainCount),
            HostCount = Math.Max(0, HostCount),
            Operations = Operations,
            RequireFullCertificate = RequireFullCertificate,
            RequestsPerDomain = Math.Max(1, RequestsPerDomain),
            RequestsPerHost = Math.Max(1, RequestsPerHost),
            HydrationRequestsPerCertificate = Math.Max(0, HydrationRequestsPerCertificate),
            EstimatedCertificatesToHydrate = Math.Max(0, EstimatedCertificatesToHydrate)
        };
    }
}

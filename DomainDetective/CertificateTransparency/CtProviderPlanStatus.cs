namespace DomainDetective;

/// <summary>
/// Describes the service-facing status of a planned certificate transparency provider workload.
/// </summary>
public enum CtProviderPlanStatus
{
    /// <summary>The provider cannot satisfy the requested workload.</summary>
    Unsupported = 0,

    /// <summary>The provider can satisfy the workload, but should be retried later.</summary>
    Deferred = 1,

    /// <summary>The provider can satisfy the workload and is eligible to run now.</summary>
    Ready = 2
}

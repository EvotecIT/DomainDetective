namespace DomainDetective;

/// <summary>
/// Represents a provider-specific certificate transparency work plan.
/// </summary>
public sealed class CtProviderWorkPlan
{
    /// <summary>Provider identifier used for this plan.</summary>
    public string ProviderId { get; init; } = string.Empty;

    /// <summary>Provider plan status.</summary>
    public CtProviderPlanStatus Status { get; init; }

    /// <summary>Provider workload estimate.</summary>
    public CtIngestionWorkloadEstimate Estimate { get; init; } = new();

    /// <summary>Provider execution decision.</summary>
    public CtProviderExecutionDecision? Decision { get; init; }

    /// <summary>Human-readable reason describing this plan.</summary>
    public string Reason { get; init; } = string.Empty;
}

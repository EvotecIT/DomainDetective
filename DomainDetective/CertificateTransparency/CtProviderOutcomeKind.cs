namespace DomainDetective;

/// <summary>
/// Describes the observed outcome of one certificate transparency provider request.
/// </summary>
public enum CtProviderOutcomeKind
{
    /// <summary>The provider request completed successfully.</summary>
    Success = 0,

    /// <summary>The provider request failed with a retryable/transient error.</summary>
    TransientFailure = 1,

    /// <summary>The provider request failed because the provider rate-limited the caller.</summary>
    RateLimited = 2,

    /// <summary>The provider request timed out.</summary>
    Timeout = 3,

    /// <summary>The provider request failed with a non-retryable error.</summary>
    PermanentFailure = 4
}

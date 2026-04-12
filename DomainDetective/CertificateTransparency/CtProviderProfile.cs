using System;

namespace DomainDetective;

/// <summary>
/// Describes a certificate transparency provider and its safe default behavior.
/// </summary>
public sealed class CtProviderProfile
{
    /// <summary>Stable provider identifier used in persisted state and diagnostics.</summary>
    public string ProviderId { get; init; } = string.Empty;

    /// <summary>Human-readable provider name.</summary>
    public string DisplayName { get; init; } = string.Empty;

    /// <summary>Provider capabilities that callers can use to select the right CT path.</summary>
    public CtProviderCapabilities Capabilities { get; init; }

    /// <summary>Provider rate limit and retry profile.</summary>
    public CtProviderRateLimitProfile RateLimit { get; init; } = new();

    /// <summary>Optional note describing assumptions behind the default profile.</summary>
    public string? Notes { get; init; }

    /// <summary>Returns true when the provider advertises all requested capabilities.</summary>
    /// <param name="capabilities">Capabilities required by the caller.</param>
    public bool Supports(CtProviderCapabilities capabilities)
    {
        return (Capabilities & capabilities) == capabilities;
    }
}

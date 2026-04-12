using System;

namespace DomainDetective;

/// <summary>
/// Represents a typed failure returned by a certificate transparency provider.
/// </summary>
public sealed class CtProviderQueryException : Exception {
    /// <summary>
    /// Creates a typed CT provider exception.
    /// </summary>
    public CtProviderQueryException(
        string providerId,
        CtProviderOutcomeKind outcomeKind,
        string message,
        Exception? innerException = null,
        string? providerErrorCode = null,
        TimeSpan? retryAfter = null)
        : base(message, innerException) {
        ProviderId = providerId ?? string.Empty;
        OutcomeKind = outcomeKind;
        ProviderErrorCode = providerErrorCode;
        RetryAfter = retryAfter;
    }

    /// <summary>Provider that produced the failure.</summary>
    public string ProviderId { get; }

    /// <summary>Normalized provider outcome kind for scheduler decisions.</summary>
    public CtProviderOutcomeKind OutcomeKind { get; }

    /// <summary>Provider-specific status, such as a PostgreSQL SQLSTATE or HTTP status code.</summary>
    public string? ProviderErrorCode { get; }

    /// <summary>Provider-suggested retry delay, when known.</summary>
    public TimeSpan? RetryAfter { get; }
}

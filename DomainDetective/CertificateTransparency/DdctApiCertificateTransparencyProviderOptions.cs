using System;

namespace DomainDetective;

/// <summary>
/// Options for querying a DomainDetectiveCertificateTransparency API endpoint as a CT provider.
/// </summary>
public sealed class DdctApiCertificateTransparencyProviderOptions
{
    /// <summary>Default DDCT API endpoint when none is provided.</summary>
    public const string DefaultEndpointUrl = "http://127.0.0.1:8080";

    /// <summary>Default request header for DDCT API keys.</summary>
    public const string DefaultApiKeyHeaderName = "X-DDCT-Api-Key";

    /// <summary>Default certificate or observation page size.</summary>
    public const int DefaultQueryPageSize = 100;

    /// <summary>Maximum allowed page size.</summary>
    public const int MaxQueryPageSize = 500;

    /// <summary>Default maximum pages fetched for a single logical query.</summary>
    public const int DefaultMaxPagesPerQuery = 5;

    /// <summary>Maximum allowed pages fetched for a single logical query.</summary>
    public const int MaxAllowedPagesPerQuery = 25;

    /// <summary>Base API endpoint URL.</summary>
    public string EndpointUrl { get; set; } = DefaultEndpointUrl;

    /// <summary>Optional API key used when the DDCT API requires authentication.</summary>
    public string? ApiKey { get; set; }

    /// <summary>Request header name for the API key. Use <c>Authorization</c> for bearer auth.</summary>
    public string ApiKeyHeaderName { get; set; } = DefaultApiKeyHeaderName;

    /// <summary>Optional DDCT logical scope to constrain queries.</summary>
    public string? ScopeName { get; set; }

    /// <summary>Default page size when the query does not request one explicitly.</summary>
    public int QueryPageSize { get; set; } = DefaultQueryPageSize;

    /// <summary>Maximum pages fetched before the provider returns a truncated result with diagnostics.</summary>
    public int MaxPagesPerQuery { get; set; } = DefaultMaxPagesPerQuery;
}

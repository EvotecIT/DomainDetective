namespace DomainDetective;

using System.Collections.Generic;

/// <summary>
/// Result of a single Autodiscover endpoint check.
/// </summary>
public class AutodiscoverEndpointResult {
    /// <summary>Gets the discovery method that produced this result.</summary>
    public AutodiscoverMethod Method { get; init; }
    /// <summary>Gets the URL that was checked.</summary>
    public string? Url { get; init; }
    /// <summary>Gets the HTTP status code returned.</summary>
    public int StatusCode { get; init; }
    /// <summary>Gets the chain of redirects followed, if any.</summary>
    public IReadOnlyList<string>? RedirectChain { get; init; }
    /// <summary>Gets a value indicating whether the XML response was valid.</summary>
    public bool XmlValid { get; init; }
    /// <summary>Gets whether a supported Autodiscover settings, redirect or error structure was recognized.</summary>
    public bool ServiceResponseRecognized { get; init; }
    /// <summary>Gets the recognized response kind; an error response does not prove mailbox authentication.</summary>
    public string? ServiceResponseType { get; init; }
    /// <summary>Gets whether this response confirms an Autodiscover service rather than merely well-formed XML or a JSON candidate URL.</summary>
    public bool DiscoverySucceeded => StatusCode >= 200 && StatusCode < 300 && XmlValid && XmlNamespaceValid && ServiceResponseRecognized;
    /// <summary>Gets a retained request or body failure.</summary>
    public string? Error { get; init; }
    /// <summary>Gets whether the overall flow deadline ended this endpoint.</summary>
    public bool BudgetExhausted { get; init; }
    /// <summary>Gets endpoint duration, including GET, redirects, POST and response bodies.</summary>
    public long ElapsedMilliseconds { get; init; }
    /// <summary>Gets individual requests and their observed failure phases.</summary>
    public IReadOnlyList<AutodiscoverRequestAttempt> Requests { get; init; } = System.Array.Empty<AutodiscoverRequestAttempt>();
    /// <summary>Gets the final URL after following redirects, if any.</summary>
    public string? FinalUrl { get; init; }
    /// <summary>Gets the host of the final URL.</summary>
    public string? FinalHost { get; init; }
    /// <summary>Gets the Content-Type from the response, if available.</summary>
    public string? ContentType { get; init; }
    /// <summary>Gets a short snippet of the response body for diagnostics.</summary>
    public string? ContentSnippet { get; init; }
    /// <summary>Heuristic indicating the content looks like HTML (error page).</summary>
    public bool ContentLooksHtml { get; init; }
    /// <summary>XML namespace of the root element, when XML was returned.</summary>
    public string? XmlNamespace { get; init; }
    /// <summary>Indicates whether the XML namespace matches expected Autodiscover schemas.</summary>
    public bool XmlNamespaceValid { get; init; }
    /// <summary>Gets a value indicating whether a JSON response indicated a valid Autodiscover endpoint.</summary>
    public bool JsonValid { get; init; }
    /// <summary>Gets the endpoint URL discovered via JSON, if any.</summary>
    public string? JsonEndpointUrl { get; init; }
}

/// <summary>Observed timing and response evidence for one anonymous Autodiscover HTTP request.</summary>
public sealed class AutodiscoverRequestAttempt {
    /// <summary>Gets the attempted URL.</summary>
    public string Url { get; init; } = string.Empty;
    /// <summary>Gets the HTTP method.</summary>
    public string Method { get; init; } = string.Empty;
    /// <summary>Gets the response status when headers arrived.</summary>
    public int? StatusCode { get; init; }
    /// <summary>Gets duration through body acquisition or failure.</summary>
    public long ElapsedMilliseconds { get; init; }
    /// <summary>Gets request or body when a failure occurred; connection-only timing is not inferred.</summary>
    public string? FailureStage { get; init; }
    /// <summary>Gets the failure detail.</summary>
    public string? Error { get; init; }
}

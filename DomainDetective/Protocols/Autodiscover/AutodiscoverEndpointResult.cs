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

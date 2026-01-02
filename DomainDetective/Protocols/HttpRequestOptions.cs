namespace DomainDetective;

using System;
using System.Collections.Generic;
using System.Net.Http;

/// <summary>
/// HTTP method used for web posture checks.
/// </summary>
public enum HttpRequestMethod
{
    Head = 0,
    Get = 1,
    Post = 2,
    Put = 3,
    Delete = 4,
    Options = 5,
    Trace = 6,
    Patch = 7
}

/// <summary>
/// Request customization options for <see cref="HttpAnalysis"/>.
/// </summary>
public sealed class HttpRequestOptions
{
    /// <summary>HTTP method to use for the request.</summary>
    public HttpRequestMethod Method { get; set; } = HttpRequestMethod.Get;

    /// <summary>
    /// When true, disables TLS certificate validation (unsafe; off by default).
    /// </summary>
    public bool DisableTlsValidation { get; set; }

    /// <summary>Optional proxy URL (e.g. http://127.0.0.1:8080).</summary>
    public string? ProxyUrl { get; set; }

    /// <summary>Optional Cookie header value to send.</summary>
    public string? Cookie { get; set; }

    /// <summary>Additional request headers to send.</summary>
    public Dictionary<string, string> Headers { get; } = new(StringComparer.OrdinalIgnoreCase);

    private static readonly HttpMethod PatchMethod = new HttpMethod("PATCH");

    internal HttpMethod ToHttpMethod()
    {
        return Method switch
        {
            HttpRequestMethod.Head => HttpMethod.Head,
            HttpRequestMethod.Get => HttpMethod.Get,
            HttpRequestMethod.Post => HttpMethod.Post,
            HttpRequestMethod.Put => HttpMethod.Put,
            HttpRequestMethod.Delete => HttpMethod.Delete,
            HttpRequestMethod.Options => HttpMethod.Options,
            HttpRequestMethod.Trace => HttpMethod.Trace,
            HttpRequestMethod.Patch => PatchMethod,
            _ => HttpMethod.Get
        };
    }
}

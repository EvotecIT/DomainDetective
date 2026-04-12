namespace DomainDetective;

using System;
using System.Collections.Generic;
using System.Net.Http;

/// <summary>
/// HTTP method used for web posture checks.
/// </summary>
public enum HttpRequestMethod
{
    /// <summary>Provides http request options functionality.</summary>
    Head = 0,
    /// <summary>Provides http request options functionality.</summary>
    Get = 1,
    /// <summary>Provides http request options functionality.</summary>
    Post = 2,
    /// <summary>Provides http request options functionality.</summary>
    Put = 3,
    /// <summary>Provides http request options functionality.</summary>
    Delete = 4,
    /// <summary>Provides http request options functionality.</summary>
    Options = 5,
    /// <summary>Provides http request options functionality.</summary>
    Trace = 6,
    /// <summary>Provides http request options functionality.</summary>
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

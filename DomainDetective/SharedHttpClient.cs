using System;
using System.Net.Http;

namespace DomainDetective;

/// <summary>
/// Provides a single static <see cref="HttpClient"/> instance for the process.
/// </summary>
public sealed class SharedHttpClient : IHttpClientFactory
{
    /// <summary>
    /// Gets the shared <see cref="HttpClient"/> instance.
    /// </summary>
    public static readonly HttpClient Instance;

    static SharedHttpClient()
    {
        Instance = new HttpClient();
        AppDomain.CurrentDomain.ProcessExit += (_, _) => Instance.Dispose();
    }

    /// <inheritdoc/>
    public HttpClient CreateClient() => Instance;
}

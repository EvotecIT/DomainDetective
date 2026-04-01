using System;
using System.IO;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

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
        NetFrameworkTls.EnsureEnabled();
        Instance = new HttpClient();
        Instance.DefaultRequestHeaders.UserAgent.ParseAdd("DomainDetective/1.0 (+https://github.com/EvotecIT/DomainDetective)");
        AppDomain.CurrentDomain.ProcessExit += (_, _) => Instance.Dispose();
    }

    /// <inheritdoc/>
    public HttpClient CreateClient() => Instance;

    /// <summary>
    /// Retrieves content with retry logic for transient network errors.
    /// </summary>
    /// <param name="url">Request URL.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <param name="attempts">Maximum retry attempts.</param>
    /// <returns>Downloaded string content.</returns>
    public static async Task<string> GetStringWithRetryAsync(
        string url,
        CancellationToken ct,
        int attempts = 3)
    {
        Exception? last = null;

        for (var i = 0; i < attempts; i++)
        {
            try
            {
                using var response = await Instance.GetAsync(url, ct).ConfigureAwait(false);
                response.EnsureSuccessStatusCode();
                return await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is HttpRequestException || ex is IOException)
            {
                last = ex;
                if (i < attempts - 1)
                {
                    await Task.Delay(1000, ct).ConfigureAwait(false);
                }
            }
        }

        throw last!;
    }
}

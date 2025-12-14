namespace DomainDetective;

using System;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

/// <summary>
/// Client for querying VirusTotal API.
/// </summary>
public sealed class VirusTotalClient
{
    /// <summary>Base URL of the service.</summary>
    public string BaseUrl { get; }

    /// <summary>API key for authentication.</summary>
    public string? ApiKey { get; set; }

    /// <summary>Factory for creating custom HTTP handlers.</summary>
    internal Func<HttpMessageHandler>? HttpHandlerFactory { get; set; }

    /// <summary>
    /// Initializes a new instance of the <see cref="VirusTotalClient"/> class.
    /// </summary>
    /// <param name="apiKey">VirusTotal API key.</param>
    /// <param name="baseUrl">Optional base URL.</param>
    public VirusTotalClient(string? apiKey = null, string? baseUrl = null)
    {
        ApiKey = apiKey;
        if (baseUrl != null && !string.IsNullOrWhiteSpace(baseUrl))
        {
            BaseUrl = baseUrl.TrimEnd('/');
        }
        else
        {
            BaseUrl = "https://www.virustotal.com/api/v3";
        }
    }

    private HttpClient GetClient(out bool dispose)
    {
        if (HttpHandlerFactory != null)
        {
            dispose = true;
            return new HttpClient(HttpHandlerFactory(), disposeHandler: true);
        }

        dispose = false;
        return SharedHttpClient.Instance;
    }

    private async Task<T?> QueryAsync<T>(string path, CancellationToken ct)
    {
        var client = GetClient(out var dispose);
        try
        {
            var request = new HttpRequestMessage(HttpMethod.Get, $"{BaseUrl}/{path}");
            if (!string.IsNullOrEmpty(ApiKey))
            {
                request.Headers.Add("x-apikey", ApiKey);
            }

            using var resp = await client.SendAsync(request, ct).ConfigureAwait(false);
            resp.EnsureSuccessStatusCode();
            var json = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
            return JsonSerializer.Deserialize<T>(json, VirusTotalJson.Options);
        }
        finally
        {
            if (dispose)
            {
                client.Dispose();
            }
        }
    }

    /// <summary>Gets domain information.</summary>
    public Task<VirusTotalResponse?> GetDomain(string domain, CancellationToken ct = default)
        => QueryAsync<VirusTotalResponse>($"domains/{domain}", ct);

    /// <summary>Gets IP address information.</summary>
    public Task<VirusTotalResponse?> GetIpAddress(string ipAddress, CancellationToken ct = default)
        => QueryAsync<VirusTotalResponse>($"ip_addresses/{ipAddress}", ct);

    /// <summary>Gets URL information.</summary>
    public Task<VirusTotalResponse?> GetUrl(string urlId, CancellationToken ct = default)
        => QueryAsync<VirusTotalResponse>($"urls/{urlId}", ct);
}

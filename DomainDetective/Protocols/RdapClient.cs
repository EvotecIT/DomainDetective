namespace DomainDetective;

using System;
using System.Net.Http;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

/// <summary>
/// Provides methods for querying RDAP resources.
/// </summary>
public sealed class RdapClient
{
    /// <summary>Base URL of the RDAP service.</summary>
    public string BaseUrl { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="RdapClient"/> class.
    /// </summary>
    /// <param name="baseUrl">Service endpoint. Defaults to rdap.org.</param>
    public RdapClient(string? baseUrl = null)
    {
        if (baseUrl != null && !string.IsNullOrWhiteSpace(baseUrl))
        {
            BaseUrl = baseUrl.TrimEnd('/');
        }
        else
        {
            BaseUrl = "https://rdap.org";
        }
    }

    private async Task<T?> QueryAsync<T>(string path, CancellationToken ct)
    {
        if (!BaseUrl.StartsWith("http", StringComparison.OrdinalIgnoreCase))
        {
            string basePath = BaseUrl.StartsWith("file://", StringComparison.OrdinalIgnoreCase)
                ? new Uri(BaseUrl).LocalPath
                : BaseUrl;
            string file = Path.Combine(basePath, path + ".json");
            string json;
            ct.ThrowIfCancellationRequested();
            json = File.ReadAllText(file);
            ct.ThrowIfCancellationRequested();
            return JsonSerializer.Deserialize<T>(json, RdapJson.Options);
        }

        string networkJson = await SharedHttpClient
            .GetStringWithRetryAsync($"{BaseUrl}/{path}", ct)
            .ConfigureAwait(false);
        return JsonSerializer.Deserialize<T>(networkJson, RdapJson.Options);
    }

    /// <summary>Queries domain information.</summary>
    public Task<RdapDomain?> QueryDomainAsync(string domain, CancellationToken ct = default)
        => QueryAsync<RdapDomain>($"domain/{domain}", ct);

    /// <summary>Queries domain information.</summary>
    public Task<RdapDomain?> GetDomain(string domain, CancellationToken ct = default)
        => QueryDomainAsync(domain, ct);

    /// <summary>Queries top-level domain information.</summary>
    public Task<RdapDomain?> QueryTldAsync(string tld, CancellationToken ct = default)
        => QueryDomainAsync(tld, ct);

    /// <summary>Queries top-level domain information.</summary>
    public Task<RdapDomain?> GetTld(string tld, CancellationToken ct = default)
        => QueryTldAsync(tld, ct);

    /// <summary>Queries IP network information.</summary>
    public Task<RdapIpNetwork?> QueryIpAsync(string ipOrCidr, CancellationToken ct = default)
        => QueryAsync<RdapIpNetwork>($"ip/{ipOrCidr}", ct);

    /// <summary>Queries IP network information.</summary>
    public Task<RdapIpNetwork?> GetIp(string ipOrCidr, CancellationToken ct = default)
        => QueryIpAsync(ipOrCidr, ct);

    /// <summary>Queries autonomous system information.</summary>
    public Task<RdapAutnum?> QueryAutnumAsync(string asNumber, CancellationToken ct = default)
        => QueryAsync<RdapAutnum>($"autnum/{asNumber}", ct);

    /// <summary>Queries autonomous system information.</summary>
    public Task<RdapAutnum?> GetAutnum(string asNumber, CancellationToken ct = default)
        => QueryAutnumAsync(asNumber, ct);

    /// <summary>Queries entity information.</summary>
    public Task<RdapEntity?> QueryEntityAsync(string handle, CancellationToken ct = default)
        => QueryAsync<RdapEntity>($"entity/{handle}", ct);

    /// <summary>Queries entity information.</summary>
    public Task<RdapEntity?> GetEntity(string handle, CancellationToken ct = default)
        => QueryEntityAsync(handle, ct);

    /// <summary>Queries registrar information.</summary>
    public Task<RdapEntity?> QueryRegistrarAsync(string handle, CancellationToken ct = default)
        => QueryEntityAsync(handle, ct);

    public Task<RdapEntity?> GetRegistrar(string handle, CancellationToken ct = default)
        => QueryRegistrarAsync(handle, ct);

    /// <summary>Queries nameserver information.</summary>
    public Task<RdapNameserver?> QueryNameserverAsync(string host, CancellationToken ct = default)
        => QueryAsync<RdapNameserver>($"nameserver/{host}", ct);

    public Task<RdapNameserver?> GetNameserver(string host, CancellationToken ct = default)
        => QueryNameserverAsync(host, ct);
}

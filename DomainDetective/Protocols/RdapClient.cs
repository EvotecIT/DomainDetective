namespace DomainDetective;

using System.Net.Http;
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
        BaseUrl = string.IsNullOrWhiteSpace(baseUrl) ? "https://rdap.org" : baseUrl.TrimEnd('/');
    }

    private async Task<T?> QueryAsync<T>(string path, CancellationToken ct)
    {
        var client = SharedHttpClient.Instance;
#if NETSTANDARD2_0 || NET472
        using var response = await client.GetAsync($"{BaseUrl}/{path}", ct).ConfigureAwait(false);
        var json = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
#else
        var json = await client.GetStringAsync($"{BaseUrl}/{path}", ct).ConfigureAwait(false);
#endif
        return JsonSerializer.Deserialize<T>(json, RdapJson.Options);
    }

    /// <summary>Queries domain information.</summary>
    public Task<RdapDomain?> GetDomain(string domain, CancellationToken ct = default)
        => QueryAsync<RdapDomain>($"domain/{domain}", ct);

    /// <summary>Queries top-level domain information.</summary>
    public Task<RdapDomain?> GetTld(string tld, CancellationToken ct = default)
        => GetDomain(tld, ct);

    /// <summary>Queries IP network information.</summary>
    public Task<RdapIpNetwork?> GetIp(string ipOrCidr, CancellationToken ct = default)
        => QueryAsync<RdapIpNetwork>($"ip/{ipOrCidr}", ct);

    /// <summary>Queries autonomous system information.</summary>
    public Task<RdapAutnum?> GetAutnum(string asNumber, CancellationToken ct = default)
        => QueryAsync<RdapAutnum>($"autnum/{asNumber}", ct);

    /// <summary>Queries entity information.</summary>
    public Task<RdapEntity?> GetEntity(string handle, CancellationToken ct = default)
        => QueryAsync<RdapEntity>($"entity/{handle}", ct);

    /// <summary>Queries registrar information.</summary>
    public Task<RdapEntity?> GetRegistrar(string handle, CancellationToken ct = default)
        => GetEntity(handle, ct);

    /// <summary>Queries nameserver information.</summary>
    public Task<RdapNameserver?> GetNameserver(string host, CancellationToken ct = default)
        => QueryAsync<RdapNameserver>($"nameserver/{host}", ct);
}

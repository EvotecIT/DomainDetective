using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Queries RDAP servers for domain registration data.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public class RdapAnalysis
{
    /// <summary>Domain name returned by the RDAP server.</summary>
    public string DomainName { get; private set; } = string.Empty;
    /// <summary>Registrar display name.</summary>
    public string? Registrar { get; private set; }
    /// <summary>Registrar identifier.</summary>
    public string? RegistrarId { get; private set; }
    /// <summary>Domain creation date string.</summary>
    public string? CreationDate { get; private set; }
    /// <summary>Domain expiration date string.</summary>
    public string? ExpiryDate { get; private set; }
    /// <summary>List of authoritative name servers.</summary>
    public List<string> NameServers { get; private set; } = new();
    /// <summary>Status values reported by RDAP.</summary>
    public List<string> Status { get; private set; } = new();
    /// <summary>Deserialized RDAP domain data.</summary>
    public RdapDomain? DomainData { get; private set; }

    internal Func<string, Task<string>>? QueryOverride { get; set; }

    /// <summary>
    /// Retrieves RDAP information for <paramref name="domain"/>.
    /// </summary>
    /// <param name="domain">Domain to query.</param>
    /// <param name="logger">Optional logger for diagnostics.</param>
    /// <param name="cancellationToken">Token used to cancel the operation.</param>
    public async Task Analyze(string domain, InternalLogger? logger = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            throw new ArgumentNullException(nameof(domain));
        }

        DomainName = domain;
        Registrar = null;
        RegistrarId = null;
        CreationDate = null;
        ExpiryDate = null;
        NameServers = new List<string>();
        Status = new List<string>();

        string json;
        if (QueryOverride != null)
        {
            json = await QueryOverride(domain).ConfigureAwait(false);
        }
        else
        {
            HttpClient client = SharedHttpClient.Instance;
#if NETSTANDARD2_0 || NET472
            using var response = await client.GetAsync($"https://rdap.org/domain/{domain}", cancellationToken).ConfigureAwait(false);
            json = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
#else
            json = await client.GetStringAsync($"https://rdap.org/domain/{domain}", cancellationToken).ConfigureAwait(false);
#endif
        }

        DomainData = JsonSerializer.Deserialize<RdapDomain>(json, RdapJson.Options);
        if (DomainData == null)
        {
            return;
        }

        DomainName = DomainData.LdhName ?? DomainName;

        if (DomainData.Status != null)
        {
            Status = DomainData.Status
                .Where(s => s != RdapStatus.Unknown)
                .Select(s =>
                {
                    var text = s.ToString();
                    return char.ToLowerInvariant(text[0]) + text.Substring(1);
                })
                .ToList();
        }

        if (DomainData.Nameservers != null)
        {
            NameServers = DomainData.Nameservers
                .Select(n => n.LdhName)
                .Where(n => !string.IsNullOrEmpty(n))
                .Select(n => n!)
                .ToList();
        }

        if (DomainData.Entities != null)
        {
            foreach (var ent in DomainData.Entities)
            {
                if (ent.Roles.Any(r => string.Equals(r, "registrar", StringComparison.OrdinalIgnoreCase)))
                {
                    RegistrarId ??= ent.Handle;
                    if (ent.VcardArray.HasValue && ent.VcardArray.Value.ValueKind == JsonValueKind.Array && ent.VcardArray.Value.GetArrayLength() > 1)
                    {
                        foreach (var card in ent.VcardArray.Value[1].EnumerateArray())
                        {
                            if (card.GetArrayLength() > 3 && card[0].GetString() == "fn")
                            {
                                Registrar = card[3].GetString();
                                break;
                            }
                        }
                    }
                }
            }
        }

        if (DomainData.Events != null)
        {
            foreach (var ev in DomainData.Events)
            {
                if (ev.Action == RdapEventAction.Registration)
                {
                    CreationDate = ev.Date;
                }
                else if (ev.Action == RdapEventAction.Expiration)
                {
                    ExpiryDate = ev.Date;
                }
            }
        }
    }
}

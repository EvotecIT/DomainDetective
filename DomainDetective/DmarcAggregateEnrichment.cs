using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Enriches DMARC aggregate records with ASN and country info.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public static class DmarcAggregateEnrichment
{
    private static readonly GeoIpAnalysis _geo = new GeoIpAnalysis();
    private static bool _geoLoaded = false;

    public static async Task EnrichAsync(IEnumerable<DmarcAggregateRecord> records, CancellationToken ct = default)
    {
        if (!_geoLoaded)
        {
            try { _geo.LoadBuiltinDatabase(); } catch { }
            _geoLoaded = true;
        }

        var list = records?.ToList() ?? new List<DmarcAggregateRecord>();
        var ips = list.Select(r => r.SourceIp).Where(ip => !string.IsNullOrWhiteSpace(ip)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

        var asnMap = new Dictionary<string, int?>();
        foreach (var ip in ips)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                var asn = await LookupAsnAsync(ip, ct).ConfigureAwait(false);
                asnMap[ip] = asn;
            }
            catch { asnMap[ip] = null; }
        }

        foreach (var r in list)
        {
            if (!string.IsNullOrWhiteSpace(r.SourceIp))
            {
                asnMap.TryGetValue(r.SourceIp, out var asn);
                r.Asn = asn;
                r.Country = _geo.Lookup(r.SourceIp)?.Country;
            }
        }
    }

    // Simplified RIPE Stat lookup similar to DnsPropagationAnalysis.LookupAsnAsync
    private static async Task<int?> LookupAsnAsync(string ip, CancellationToken ct)
    {
        var url = $"https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}";
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        using var response = await SharedHttpClient.Instance.SendAsync(request, ct).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode) return null;
#if NET8_0_OR_GREATER
        using var stream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
#else
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#endif
        using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct).ConfigureAwait(false);
        if (!doc.RootElement.TryGetProperty("data", out var data) || !data.TryGetProperty("asns", out var asns)) return null;
        if (asns.GetArrayLength() == 0) return null;
        return asns[0].GetProperty("asn").GetInt32();
    }
}

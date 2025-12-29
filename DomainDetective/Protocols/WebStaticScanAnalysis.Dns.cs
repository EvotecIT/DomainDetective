using System.Threading;
using System.Threading.Tasks;
using DnsClientX;

namespace DomainDetective;

/// <summary>
/// DNS-related helpers for WebStaticScanAnalysis split out via partials to keep the core readable.
/// </summary>
public partial class WebStaticScanAnalysis
{
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, (System.DateTimeOffset ts, System.Collections.Generic.List<string> txts)> _dnsTxtCache = new();
    private static readonly System.TimeSpan _dnsTxtCacheTtl = System.TimeSpan.FromMinutes(5);
    /// <summary>
    /// Performs minimal DNS TXT detection for well-known verification records to add technology evidence.
    /// </summary>
    private async Task ApplyDnsTechDetections(string host, CancellationToken cancellationToken)
    {
        try
        {
            var namesToCheck = new System.Collections.Generic.List<string> { host };
            try
            {
                var primaryRegistrableDomain = PrimaryRegistrableDomain;
                if (primaryRegistrableDomain != null &&
                    !string.IsNullOrWhiteSpace(primaryRegistrableDomain) &&
                    !string.Equals(primaryRegistrableDomain, host, System.StringComparison.OrdinalIgnoreCase))
                {
                    namesToCheck.Add(primaryRegistrableDomain);
                }
            }
            catch { }

            foreach (var name in namesToCheck)
            {
                System.Collections.Generic.List<string>? texts = null;
                if (_dnsTxtCache.TryGetValue(name, out var cached))
                {
                    if (System.DateTimeOffset.UtcNow - cached.ts < _dnsTxtCacheTtl)
                    {
                        texts = cached.txts;
                    }
                    else
                    {
                        _dnsTxtCache.TryRemove(name, out _);
                    }
                }
                if (texts == null)
                {
                    texts = new System.Collections.Generic.List<string>();
                    var txtRecords = await DnsConfiguration.QueryDNS(
                        name,
                        DnsRecordType.TXT,
                        filter: string.Empty,
                        includeAliasesInFilter: true,
                        cancellationToken: cancellationToken).ConfigureAwait(false);
                    foreach (var rec in txtRecords)
                    {
                        var txt = rec.Data ?? rec.DataRaw ?? string.Empty;
                        if (!string.IsNullOrWhiteSpace(txt)) texts.Add(txt);
                    }
                    _dnsTxtCache[name] = (System.DateTimeOffset.UtcNow, texts);
                }
                foreach (var txt in texts) { WebTechVerificationCatalog.ApplyDnsTxt(txt, TechDetections, TechDetails); }
            }
        }
        catch { }
    }
}

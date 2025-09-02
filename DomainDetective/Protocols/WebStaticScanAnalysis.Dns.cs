using System.Threading;
using System.Threading.Tasks;
using DnsClientX;

namespace DomainDetective;

/// <summary>
/// DNS-related helpers for WebStaticScanAnalysis split out via partials to keep the core readable.
/// </summary>
public partial class WebStaticScanAnalysis
{
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
                if (!string.IsNullOrWhiteSpace(PrimaryRegistrableDomain) &&
                    !string.Equals(PrimaryRegistrableDomain, host, System.StringComparison.OrdinalIgnoreCase))
                {
                    namesToCheck.Add(PrimaryRegistrableDomain);
                }
            }
            catch { }

            foreach (var name in namesToCheck)
            {
                var txtRecords = await DnsConfiguration.QueryDNS(name, DnsRecordType.TXT, cancellationToken: cancellationToken).ConfigureAwait(false);
                foreach (var rec in txtRecords)
                {
                    var txt = rec.Data ?? rec.DataRaw ?? string.Empty;
                    if (string.IsNullOrWhiteSpace(txt)) continue;
                    WebTechVerificationCatalog.ApplyDnsTxt(txt, TechDetections, TechDetails);
                }
            }
        }
        catch { }
    }
}

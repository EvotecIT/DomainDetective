using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using DnsClientX;

namespace DomainDetective;

/// <summary>
/// Host enrichment (TLS/DNS/RDAP) for WebStaticScanAnalysis.
/// </summary>
public partial class WebStaticScanAnalysis
{
    private async Task EnrichHostsAsync(InternalLogger logger, CancellationToken cancellationToken)
    {
        logger?.WriteVerbose("[WEB] TLS probing for {0} hosts ...", Hosts.Count);
        int tlsCap = Math.Max(1, (TlsConcurrency > 0 ? TlsConcurrency : Concurrency));
        using var tlsGate = new SemaphoreSlim(tlsCap);
        var tlsTasks = Hosts.Select(async kv => {
            await tlsGate.WaitAsync(cancellationToken);
            try {
                kv.Value.Tls = await TlsProbe.ProbeAsync(kv.Key, 443, cancellationToken);
                if (kv.Value.Tls != null)
                {
                    kv.Value.TlsProtocolSummary = kv.Value.Tls.Protocol.ToString();
                    kv.Value.TlsCipherSuiteSummary = kv.Value.Tls.CipherSuite;
                }
            } catch { }
            finally { try { tlsGate.Release(); } catch { } }
        }).ToArray();
        await Task.WhenAll(tlsTasks);
        logger?.WriteVerbose("[WEB] TLS probing complete.");

        logger?.WriteVerbose("[WEB] DNS/RDAP enrichment for {0} hosts ...", Hosts.Count);
        int dnsCap = Math.Max(1, (DnsConcurrency > 0 ? DnsConcurrency : Concurrency));
        using var dnsGate = new SemaphoreSlim(dnsCap);
        var dnsTasks = Hosts.Select(async kv => {
            await dnsGate.WaitAsync(cancellationToken);
            try
            {
                var answers4 = await DnsConfiguration.QueryDNS(kv.Key, DnsRecordType.A, cancellationToken: cancellationToken);
                var answers6 = await DnsConfiguration.QueryDNS(kv.Key, DnsRecordType.AAAA, cancellationToken: cancellationToken);
                foreach (var a in answers4.Concat(answers6))
                {
                    var ip = a.Data ?? a.DataRaw;
                    if (!string.IsNullOrWhiteSpace(ip) && !kv.Value.IpAddresses.Contains(ip)) kv.Value.IpAddresses.Add(ip);
                }
                try
                {
                    if (answers6 != null && answers6.Length > 0) kv.Value.HasIPv6 = true; else kv.Value.HasIPv6 = false;
                    if (answers4 != null && answers4.Length > 0)
                    {
                        var mins = answers4.Min(x => x.TTL);
                        var maxs = answers4.Max(x => x.TTL);
                        kv.Value.ATtlMin = mins;
                        kv.Value.ATtlMax = maxs;
                    }
                    if (answers6 != null && answers6.Length > 0)
                    {
                        var mins6 = answers6.Min(x => x.TTL);
                        var maxs6 = answers6.Max(x => x.TTL);
                        kv.Value.AAAATtlMin = mins6;
                        kv.Value.AAAATtlMax = maxs6;
                    }
                }
                catch { }
                if (kv.Value.IpAddresses.Count > 0)
                {
                    var ip = kv.Value.IpAddresses[0];
                    var rdap = await new RdapClient().GetIp(ip, cancellationToken).ConfigureAwait(false);
                    kv.Value.Cidr = rdap?.Cidr;
                    kv.Value.Country = rdap?.Country;
                    if (rdap?.Entities != null)
                    {
                        foreach (var ent in rdap.Entities)
                        {
                            var handle = ent.Handle ?? string.Empty;
                            if (handle.StartsWith("AS", StringComparison.OrdinalIgnoreCase))
                            {
                                if (int.TryParse(handle.TrimStart('A', 'S', 'a', 's'), out var asn)) kv.Value.Asn = asn;
                                try
                                {
                                    if (ent.VcardArray.HasValue && ent.VcardArray.Value.ValueKind == System.Text.Json.JsonValueKind.Array && ent.VcardArray.Value.GetArrayLength() > 1)
                                    {
                                        foreach (var card in ent.VcardArray.Value[1].EnumerateArray())
                                        {
                                            if (card.GetArrayLength() > 3 && card[0].GetString() == "fn")
                                            {
                                                kv.Value.AsName = card[3].GetString();
                                                break;
                                            }
                                        }
                                    }
                                }
                                catch { }
                                break;
                            }
                        }
                    }
                }
            }
            catch { }
            finally { try { dnsGate.Release(); } catch { } }
        }).ToArray();
        await Task.WhenAll(dnsTasks);
        logger?.WriteVerbose("[WEB] DNS/RDAP enrichment complete.");

        // Infer provider from ASN/AS name when header hints were absent
        try
        {
            // Common ASN → provider mapping (best-effort offline)
            var asnMap = new System.Collections.Generic.Dictionary<int, string> {
                [13335] = "Cloudflare",
                [54113] = "Fastly",
                [20940] = "Akamai",
                [16509] = "Amazon",
                [14618] = "Amazon",
                [15169] = "Google",
                [8075] = "Microsoft",
                [32934] = "Facebook",
                [22822] = "Limelight",
            };
            foreach (var kv in Hosts)
            {
                var h = kv.Value;
                if (!string.IsNullOrWhiteSpace(h.EdgeProvider)) continue;
                var asn = h.Asn;
                var asname = h.AsName ?? string.Empty;
                string? prov = null;
                var low = asname.ToLowerInvariant();
                if (low.Contains("cloudflare")) prov = "Cloudflare";
                else if (low.Contains("fastly")) prov = "Fastly";
                else if (low.Contains("akamai")) prov = "Akamai";
                else if (low.Contains("amazon") || low.Contains("aws")) prov = "Amazon";
                else if (low.Contains("microsoft") || low.Contains("azure")) prov = "Azure";
                else if (low.Contains("google")) prov = "Google";
                if (string.IsNullOrWhiteSpace(prov) && asn.HasValue && asnMap.TryGetValue(asn.Value, out var mapped)) prov = mapped;
                if (!string.IsNullOrWhiteSpace(prov)) h.EdgeProvider = prov;
            }
        }
        catch { }
    }
}

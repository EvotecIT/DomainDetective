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
    private async Task EnrichHostsAsync(CancellationToken cancellationToken)
    {
        int tlsCap = Math.Max(1, (TlsConcurrency > 0 ? TlsConcurrency : Concurrency));
        using var tlsGate = new SemaphoreSlim(tlsCap);
        var tlsTasks = Hosts.Select(async kv => {
            await tlsGate.WaitAsync(cancellationToken);
            try { kv.Value.Tls = await TlsProbe.ProbeAsync(kv.Key, 443, cancellationToken); } catch { }
            finally { try { tlsGate.Release(); } catch { } }
        }).ToArray();
        await Task.WhenAll(tlsTasks);

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
    }
}

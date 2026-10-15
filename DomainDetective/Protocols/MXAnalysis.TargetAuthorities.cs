using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DomainDetective;

public partial class MXAnalysis {
    private async Task<DnsResponse?> QueryRecursiveResponseAsync(string owner, DnsRecordType type) {
        try {
            var response = QueryDnsOverride != null
                ? new DnsResponse { Status = DnsResponseCode.NoError, Answers = await QueryDns(owner, type) }
                : await DnsConfiguration.QueryDNSResponse(owner, type);
            return response != null && string.IsNullOrEmpty(response.Error) &&
                (response.Status == DnsResponseCode.NoError || response.Status == DnsResponseCode.NXDomain) ? response : null;
        } catch (Exception ex) when (ex is OperationCanceledException || ex is TimeoutException ||
            ex is System.Net.Sockets.SocketException || ex is System.IO.IOException || ex is System.Net.Http.HttpRequestException ||
            ex is InvalidOperationException || ex is FormatException || ex is ArgumentException || ex is DnsClientException) { return null; }
    }

    /// <summary>Uses the closest enclosing SOA in the recursive response to identify the owner's authoritative zone.</summary>
    internal async Task<string?> FindAuthoritativeZoneAsync(string owner) {
        var normalized = NormalizeHost(owner);
        var response = await QueryRecursiveResponseAsync(normalized, DnsRecordType.SOA);
        if (response == null) { return null; }
        return (response.Answers ?? Array.Empty<DnsAnswer>()).Concat(response.Authorities ?? Array.Empty<DnsAnswer>())
            .Where(answer => answer.Type == DnsRecordType.SOA)
            .Select(answer => NormalizeHost(answer.Name))
            .Where(zone => zone.Length > 0 && (normalized.Equals(zone, StringComparison.OrdinalIgnoreCase) ||
                normalized.EndsWith("." + zone, StringComparison.OrdinalIgnoreCase)))
            .OrderByDescending(zone => zone.Length).FirstOrDefault();
    }

    /// <summary>Discovers authority addresses for the subject and MX owners, sharing discovery for owners in the same zone.</summary>
    internal async Task<Dictionary<string, (List<string> Addresses, bool Incomplete)>> DiscoverComparisonAuthoritiesAsync(string domain, IEnumerable<string> mxHosts) {
        var owners = mxHosts.Append(domain).Select(NormalizeHost).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        int concurrency = Math.Max(1, Math.Min(8, DnsConfiguration.ResolverMaxConcurrency ?? 8));
        var ownerZones = await Helpers.AuthoritativeDnsProbes.RunAsync(owners,
            async owner => (Owner: owner, Zone: await FindAuthoritativeZoneAsync(owner)), concurrency);
        var zones = ownerZones.Where(item => item.Zone != null).Select(item => item.Zone!)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        var discoveries = await Helpers.AuthoritativeDnsProbes.RunAsync(zones,
            async zone => (Zone: zone, Evidence: await DiscoverAuthoritativeServersAsync(zone)), concurrency);
        var byZone = discoveries.ToDictionary(item => item.Zone, item => item.Evidence, StringComparer.OrdinalIgnoreCase);
        var result = new Dictionary<string, (List<string> Addresses, bool Incomplete)>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in ownerZones) {
            result[item.Owner] = item.Zone != null ? byZone[item.Zone] : (new List<string>(), true);
        }
        return result;
    }
}

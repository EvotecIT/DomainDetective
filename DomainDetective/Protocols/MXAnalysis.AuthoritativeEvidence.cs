using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace DomainDetective;

public partial class MXAnalysis {
    private async Task<(DnsAnswer[]? Answers, bool NxDomain)> QueryRecursiveEvidenceAsync(string owner, DnsRecordType type) {
        try {
            if (QueryDnsOverride != null) { return (await QueryDns(owner, type), false); }
            var response = await DnsConfiguration.QueryDNSResponse(owner, type);
            if (response == null || !string.IsNullOrEmpty(response.Error) ||
                response.Status != DnsResponseCode.NoError && response.Status != DnsResponseCode.NXDomain) { return (null, false); }
            return (response.Answers ?? Array.Empty<DnsAnswer>(), response.Status == DnsResponseCode.NXDomain);
        } catch (Exception ex) when (ex is OperationCanceledException || ex is TimeoutException ||
            ex is System.Net.Sockets.SocketException || ex is InvalidOperationException || ex is FormatException || ex is ArgumentException || ex is DnsClientException) { return (null, false); }
    }

    internal async Task<(List<string> Addresses, bool Incomplete)> DiscoverAuthoritativeServersAsync(string domain) {
        var ns = await QueryRecursiveEvidenceAsync(domain, DnsRecordType.NS);
        var hosts = (ns.Answers ?? Array.Empty<DnsAnswer>()).Where(answer => answer.Type == DnsRecordType.NS)
            .Select(answer => NormalizeHost(answer.Data)).Where(host => host.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        bool incomplete = ns.Answers == null || hosts.Length == 0;
        var addresses = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var host in hosts) {
            var a = QueryRecursiveEvidenceAsync(host, DnsRecordType.A);
            var aaaa = QueryRecursiveEvidenceAsync(host, DnsRecordType.AAAA);
            await Task.WhenAll(a, aaaa);
            incomplete |= a.Result.Answers == null || aaaa.Result.Answers == null;
            bool resolved = false;
            foreach (var answer in (a.Result.Answers ?? Array.Empty<DnsAnswer>()).Concat(aaaa.Result.Answers ?? Array.Empty<DnsAnswer>())) {
                if (IPAddress.TryParse(answer.Data, out var ip)) { addresses.Add(ip.ToString()); resolved = true; }
                else { incomplete = true; }
            }
            incomplete |= !resolved;
        }
        return (addresses.ToList(), incomplete);
    }

    internal void RecordRrsetCompleteness(int intendedServers, int respondingServers, string domain, InternalLogger logger, AssessmentCollector? collector = null, bool discoveryIncomplete = false) {
        MxRrsetComparisonIncomplete = discoveryIncomplete || intendedServers == 0 || respondingServers < intendedServers;
        if (MxRrsetComparisonIncomplete) {
            using var ownedCollector = collector == null ? AssessmentCollector.ForAnalysis(logger, this, category: "MX") : null;
            using ((collector ?? ownedCollector!).PushTarget(domain)) {
                logger.WriteInformationCode("MX.Rrset.ComparisonIncomplete", "Authoritative MX RRset comparison was incomplete.");
            }
        }
    }

    internal void RecordRrsetConsistency(string domain, IEnumerable<HashSet<string>> rrsets, InternalLogger logger, AssessmentCollector? collector = null) {
        var sets = rrsets.ToArray();
        if (sets.Length < 2 || sets.Skip(1).All(set => sets[0].SetEquals(set))) { return; }
        MxRrsetConsistentAcrossNs = false;
        using var ownedCollector = collector == null ? AssessmentCollector.ForAnalysis(logger, this, category: "MX") : null;
        using var scope = (collector ?? ownedCollector!).PushTarget(domain);
        logger.WriteWarningCode(MxCodes.RrsetInconsistentAcrossNs, "MX RRset differs across name servers");
    }

    internal void RecordTargetAddressEvidence(string host, IEnumerable<(DnsResponse? A, DnsResponse? Aaaa)> responses, InternalLogger logger, AssessmentCollector? collector = null) {
        var rows = responses.ToArray();
        bool incomplete = rows.Length == 0 || rows.Any(row => row.A == null || row.Aaaa == null);
        TargetAddressComparisonIncomplete |= incomplete;
        bool consistent = true;
        foreach (var type in new[] { DnsRecordType.A, DnsRecordType.AAAA }) {
            HashSet<string>? first = null;
            foreach (var row in rows) {
                var response = type == DnsRecordType.A ? row.A : row.Aaaa;
                if (response == null) { continue; }
                var answers = new HashSet<string>((response.Answers ?? Array.Empty<DnsAnswer>())
                    .Where(answer => answer.Type == type).Select(answer => answer.Data), StringComparer.OrdinalIgnoreCase);
                if (first == null) { first = answers; }
                else if (!first.SetEquals(answers)) { consistent = false; }
            }
        }
        using var ownedCollector = collector == null ? AssessmentCollector.ForAnalysis(logger, this, category: "MX") : null;
        using var scope = (collector ?? ownedCollector!).PushTarget(host);
        if (!consistent) {
            TargetAddressConsistentAcrossNs = false;
            logger.WriteWarningCode(MxCodes.TargetAddressInconsistentAcrossNs, "A/AAAA differs across name servers");
        }
        if (incomplete) {
            logger.WriteInformationCode("MX.TargetAddress.ComparisonIncomplete", "Authoritative MX address comparison was incomplete for {0}.", host);
        }
    }
}

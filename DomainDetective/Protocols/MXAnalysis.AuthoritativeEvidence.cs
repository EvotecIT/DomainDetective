using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective;

public partial class MXAnalysis {
    internal void RecordRrsetCompleteness(int intendedServers, int respondingServers, string domain, InternalLogger logger) {
        MxRrsetComparisonIncomplete = intendedServers == 0 || respondingServers < intendedServers;
        if (MxRrsetComparisonIncomplete) {
            using (AssessmentCollector.ForAnalysis(logger, this, category: "MX", target: domain)) {
                logger.WriteInformationCode("MX.Rrset.ComparisonIncomplete", "Authoritative MX RRset comparison was incomplete.");
            }
        }
    }

    internal void RecordTargetAddressEvidence(string host, IEnumerable<(DnsResponse? A, DnsResponse? Aaaa)> responses, InternalLogger logger) {
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
        using var collector = AssessmentCollector.ForAnalysis(logger, this, category: "MX", target: host);
        if (!consistent) {
            TargetAddressConsistentAcrossNs = false;
            logger.WriteWarningCode(MxCodes.TargetAddressInconsistentAcrossNs, "A/AAAA differs across name servers");
        }
        if (incomplete) {
            logger.WriteInformationCode("MX.TargetAddress.ComparisonIncomplete", "Authoritative MX address comparison was incomplete for {0}.", host);
        }
    }
}

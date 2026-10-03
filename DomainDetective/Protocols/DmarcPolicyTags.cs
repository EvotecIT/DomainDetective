using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective;

internal static class DmarcPolicyTags {
    internal static bool TryRead(string record, out Dictionary<string, string> tags) {
        tags = new Dictionary<string, string>(StringComparer.Ordinal);
        if (!DmarcAnalysis.IsDmarcPolicyRecord(record)) return false;
        foreach (string term in record.Split(';')) {
            if (string.IsNullOrWhiteSpace(term)) continue;
            int equals = term.IndexOf('=');
            if (equals <= 0) return false;
            string name = term.Substring(0, equals).Trim();
            if (tags.ContainsKey(name)) return false;
            tags.Add(name, term.Substring(equals + 1).Trim());
        }
        return tags.TryGetValue("v", out string? version) && version.Equals("DMARC1", StringComparison.OrdinalIgnoreCase);
    }

    internal static bool PolicyValue(string? value) => value == "none" || value == "quarantine" || value == "reject";

    internal static bool HasValidPolicy(Dictionary<string, string> tags) => tags.TryGetValue("p", out var policy) && PolicyValue(policy)
        && (!tags.TryGetValue("sp", out var subPolicy) || PolicyValue(subPolicy))
        && (!tags.TryGetValue("np", out var nonexistent) || PolicyValue(nonexistent));

    internal static bool HasReportingFallback(Dictionary<string, string> tags) => tags.TryGetValue("rua", out var rua)
        && rua.Split(',').Any(DmarcReportUri.IsValid);
}

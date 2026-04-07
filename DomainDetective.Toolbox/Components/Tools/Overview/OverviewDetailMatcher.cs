using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Toolbox.Components.Tools.Overview;

internal static class OverviewDetailMatcher {
    private static readonly IReadOnlyDictionary<string, string> ControlToDetailTitleMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) {
        ["SPF Lookup"] = "SPF policy",
        ["DKIM Lookup"] = "DKIM selectors",
        ["DMARC Lookup"] = "DMARC policy",
        ["MX Lookup"] = "MX routing",
        ["MTA-STS Check"] = "Transport and trust policies",
        ["TLS-RPT Check"] = "Transport and trust policies",
        ["BIMI Lookup"] = "Transport and trust policies",
        ["CAA Lookup"] = "Transport and trust policies",
        ["DANE Check"] = "Transport and trust policies",
        ["DNSSEC Check"] = "DNS infrastructure",
        ["NS Lookup"] = "DNS infrastructure",
        ["SOA Lookup"] = "DNS infrastructure"
    };

    public static DomainOverviewDetailCardView? FindMatchingDetail(
        OverviewControlCardView control,
        IReadOnlyList<DomainOverviewDetailCardView> details) {
        if (control == null) {
            throw new ArgumentNullException(nameof(control));
        }

        if (details == null || details.Count == 0) {
            return null;
        }

        if (string.IsNullOrWhiteSpace(control.Title)) {
            return null;
        }

        if (ControlToDetailTitleMap.TryGetValue(control.Title, out string? expectedTitle)) {
            return details.FirstOrDefault(detail => string.Equals(detail.Title, expectedTitle, StringComparison.OrdinalIgnoreCase));
        }

        return details.FirstOrDefault(detail => string.Equals(detail.Title, control.Title, StringComparison.OrdinalIgnoreCase));
    }
}

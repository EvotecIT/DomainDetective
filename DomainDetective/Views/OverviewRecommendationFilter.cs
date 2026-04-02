using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static class OverviewRecommendationFilter {
    public static IReadOnlyList<RecommendationAdvice> ForProblems(IEnumerable<Assessment> assessments) {
        return RecommendationEngine.FromProblems(assessments ?? Array.Empty<Assessment>());
    }

    public static IReadOnlyList<RecommendationAdvice> ForPositives(IEnumerable<Assessment> assessments) {
        var grouped = RecommendationEngine.GroupByCode(
            assessments?.Where(static assessment => assessment != null && assessment.Severity == AssessmentSeverity.Info)
            ?? Array.Empty<Assessment>());

        return grouped
            .Where(static item => IsMeaningfulPositive(item))
            .Select(static item => item.Advice)
            .ToArray();
    }

    private static bool IsMeaningfulPositive(RecommendationView view) {
        var code = view.Code ?? string.Empty;
        var advice = view.Advice;
        var title = advice.Title ?? string.Empty;

        if (HasSuppressedPositiveCode(code)) {
            return false;
        }

        if (HasSuppressedPositiveTitle(title)) {
            return false;
        }

        return true;
    }

    private static bool HasSuppressedPositiveCode(string code) {
        if (string.IsNullOrWhiteSpace(code)) {
            return false;
        }

        return code.StartsWith("DNSINV.", StringComparison.OrdinalIgnoreCase) ||
               code.StartsWith("HTTP.Header.Present.", StringComparison.OrdinalIgnoreCase) ||
               code.StartsWith("SOA.", StringComparison.OrdinalIgnoreCase) ||
               code.StartsWith("TTL.", StringComparison.OrdinalIgnoreCase) ||
               code.StartsWith("DNS.TTL.", StringComparison.OrdinalIgnoreCase) ||
               code.StartsWith("CONTACT.", StringComparison.OrdinalIgnoreCase) ||
               code.Equals("RDAP.Expiry.Future", StringComparison.OrdinalIgnoreCase) ||
               code.Equals("WHOIS.Contact.Valid", StringComparison.OrdinalIgnoreCase) ||
               code.Equals("NS.Diversity.High", StringComparison.OrdinalIgnoreCase) ||
               code.Equals("MX.Success.SingleMX.ProviderAllowed", StringComparison.OrdinalIgnoreCase) ||
               code.Equals("SUBDOM.CT.ResultsPresent", StringComparison.OrdinalIgnoreCase) ||
               code.Equals("SPF.Record.Present", StringComparison.OrdinalIgnoreCase) ||
               code.Equals("SPF.Record.StartsV1", StringComparison.OrdinalIgnoreCase) ||
               code.Equals("SPF.Lookups.WithinLimit", StringComparison.OrdinalIgnoreCase) ||
               code.Equals("SPF.Include.ChainValid", StringComparison.OrdinalIgnoreCase) ||
               code.Equals("SPF.Flattened.IpSetOptimized", StringComparison.OrdinalIgnoreCase) ||
               code.Equals("DMARC.Record.Present", StringComparison.OrdinalIgnoreCase) ||
               code.Equals("DMARC.Record.StartsV1", StringComparison.OrdinalIgnoreCase) ||
               code.Equals("DKIM.Record.Present", StringComparison.OrdinalIgnoreCase) ||
               code.Equals("DKIM.Record.StartsV1", StringComparison.OrdinalIgnoreCase) ||
               code.Equals("DKIM.Key.Present", StringComparison.OrdinalIgnoreCase) ||
               code.Equals("DKIM.KeyType.Valid", StringComparison.OrdinalIgnoreCase) ||
               code.Equals("DKIM.Flags.Valid", StringComparison.OrdinalIgnoreCase) ||
               code.Equals("DKIM.Key.Rsa2048Plus", StringComparison.OrdinalIgnoreCase) ||
               code.Equals("DKIM.Selector.Aligned", StringComparison.OrdinalIgnoreCase) ||
               code.Equals("TLSRPT.Record.Present", StringComparison.OrdinalIgnoreCase) ||
               code.Equals("TLSRPT.Record.StartsV1", StringComparison.OrdinalIgnoreCase) ||
               code.Equals("m365-auth-native-credential-flow-detected", StringComparison.OrdinalIgnoreCase) ||
               code.Equals("m365-auth-probe-detected", StringComparison.OrdinalIgnoreCase) ||
               code.Equals("m365-dns-apps-detected", StringComparison.OrdinalIgnoreCase) ||
               code.Equals("m365-entra-detected", StringComparison.OrdinalIgnoreCase) ||
               code.Equals("m365-services-detected", StringComparison.OrdinalIgnoreCase);
    }

    private static bool HasSuppressedPositiveTitle(string title) {
        if (string.IsNullOrWhiteSpace(title)) {
            return false;
        }

        return title.Contains("record present", StringComparison.OrdinalIgnoreCase) ||
               title.Contains("starts with", StringComparison.OrdinalIgnoreCase) ||
               title.Contains("begins with", StringComparison.OrdinalIgnoreCase) ||
               title.Contains("public key present", StringComparison.OrdinalIgnoreCase) ||
               title.Contains("key type valid", StringComparison.OrdinalIgnoreCase) ||
               title.Contains("flags valid", StringComparison.OrdinalIgnoreCase) ||
               title.Contains("within recommended range", StringComparison.OrdinalIgnoreCase) ||
               title.Contains("matches published NS records", StringComparison.OrdinalIgnoreCase) ||
               title.Contains("contact record found", StringComparison.OrdinalIgnoreCase) ||
               title.Contains("contact record fields well-formed", StringComparison.OrdinalIgnoreCase) ||
               title.Contains("captured ", StringComparison.OrdinalIgnoreCase) ||
               title.Contains("surface probe returned", StringComparison.OrdinalIgnoreCase) ||
               title.Contains("service hints detected", StringComparison.OrdinalIgnoreCase) ||
               title.Contains("application evidence detected", StringComparison.OrdinalIgnoreCase);
    }
}

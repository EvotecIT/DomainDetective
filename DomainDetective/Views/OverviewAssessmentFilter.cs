using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

internal static class OverviewAssessmentFilter {
    private static readonly HashSet<string> InconclusiveCodes = new(StringComparer.OrdinalIgnoreCase) {
        "AUTODISC.Check.Failed",
        "AUTODISC.Office365.FlowFailed",
        "CERTHTTP.Fetch.Failed",
        "CERTHTTP.Connect.Failed",
        "DNSBL.Query.Failed",
        "DNSBL.Provider.Timeout",
        "DNSINV.Query.Failed",
        "DNSPROP.Query.Failed",
        "DKIM.Query.Failed",
        "DMARC.Query.Failed",
        "HTTP.Check.Failed",
        "HTTP.DNS.LookupFailed",
        "HTTP.Request.Failed",
        "HTTP.Request.Timeout",
        "MAILTLS.Check.Failed",
        "MTASTS.Fetch.Failed",
        "RDAP.Request.Failed",
        "SPF.Query.Failed",
        "WHOIS.Query.Failed",
        "WHOIS.IP.QueryFailed"
    };

    private static readonly string[] InconclusiveMessageMarkers = {
        "network or protocol error prevented",
        "socket operation was attempted to an unreachable network",
        "request timed out",
        "connection attempt failed",
        "check failed for",
        "request failed for",
        "query failed for"
    };

    public static IReadOnlyList<Assessment> ForOverview(IEnumerable<Assessment>? assessmentsSource, bool browserLimited) {
        if (assessmentsSource == null) {
            return Array.Empty<Assessment>();
        }

        var assessments = assessmentsSource.ToArray();
        if (assessments.Length == 0) {
            return assessments;
        }

        return assessments
            .Where(assessment => !ShouldSuppress(assessment, browserLimited))
            .ToArray();
    }

    private static bool ShouldSuppress(Assessment assessment, bool browserLimited) {
        if (assessment == null) {
            return false;
        }

        if (IsInconclusiveTransportAssessment(assessment)) {
            return true;
        }

        if (!browserLimited) {
            return false;
        }

        // Browser-safe overviews should not score checks that are only partial by design.
        return IsBrowserLimitedTransportAssessment(assessment);
    }

    private static bool IsInconclusiveTransportAssessment(Assessment assessment) {
        var code = assessment.Code ?? string.Empty;
        if (code.Length > 0 && InconclusiveCodes.Contains(code)) {
            return true;
        }

        if (string.IsNullOrWhiteSpace(assessment.Message)) {
            return false;
        }

        return InconclusiveMessageMarkers.Any(marker =>
            assessment.Message.Contains(marker, StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsBrowserLimitedTransportAssessment(Assessment assessment) {
        var code = assessment.Code ?? string.Empty;
        if (code.StartsWith("HTTP.", StringComparison.OrdinalIgnoreCase)) {
            return true;
        }

        if (code.StartsWith("CERTHTTP.", StringComparison.OrdinalIgnoreCase)) {
            return true;
        }

        if (code.StartsWith("RDAP.", StringComparison.OrdinalIgnoreCase) ||
            code.StartsWith("WHOIS.", StringComparison.OrdinalIgnoreCase)) {
            return true;
        }

        return false;
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using DomainDetective.DesiredState;

namespace DomainDetective.Recommendations;

internal sealed class DesiredStateRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        foreach (var code in GetDesiredStateCodes()) {
            if (string.IsNullOrWhiteSpace(code)) continue;
            if (!map.ContainsKey(code)) {
                map[code] = BuildAdvice(code);
            }
        }
    }

    private static IEnumerable<string> GetDesiredStateCodes() {
        var fields = typeof(DesiredStateCodes).GetFields(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic);
        foreach (var f in fields) {
            if (f.FieldType != typeof(string)) continue;
            if (f.GetValue(null) is string s && s.Length > 0) yield return s;
        }
    }

    private static RecommendationAdvice BuildAdvice(string code) {
        if (string.Equals(code, DesiredStateCodes.Conforms, StringComparison.OrdinalIgnoreCase)) {
            return new RecommendationAdvice {
                Code = code,
                Title = "Desired state baseline satisfied",
                Why = "No drift was detected against the desired state baseline.",
                How = "Keep monitoring for drift and review baselines regularly.",
                Domain = RecommendationDomain.Other,
                Tags = new[] { "desiredstate", "baseline" },
                Impact = "Confirms alignment with organizational policy.",
                Effort = RecommendationEffort.Low,
                Verify = "Re-run Test-DDDesiredState to confirm ongoing conformance."
            };
        }

        if (string.Equals(code, DesiredStateCodes.ConfigurationInvalid, StringComparison.OrdinalIgnoreCase)) {
            return new RecommendationAdvice {
                Code = code,
                Title = "Desired state configuration is invalid",
                Why = "The baseline configuration contains invalid or unsupported settings.",
                How = "Validate the desired-state JSON against the schema and fix invalid values or types.",
                Domain = RecommendationDomain.Other,
                Tags = new[] { "desiredstate", "config" },
                Impact = "Drift evaluation may be incomplete or misleading.",
                Effort = RecommendationEffort.Low,
                Verify = "Reload the configuration and confirm no errors are emitted."
            };
        }

        var area = ExtractArea(code);
        return new RecommendationAdvice {
            Code = code,
            Title = $"{area} drift from desired state",
            Why = "Current configuration does not match the desired state baseline.",
            How = "Update the live configuration to match the baseline or adjust the baseline if the deviation is intentional.",
            Domain = MapDomain(area),
            Tags = new[] { "desiredstate", area.ToLowerInvariant() },
            Impact = "Non-conformance with the organization-specific baseline.",
            Effort = RecommendationEffort.Medium,
            Verify = "Re-run Test-DDDesiredState and confirm drift is resolved."
        };
    }

    private static string ExtractArea(string code) {
        if (string.IsNullOrWhiteSpace(code)) return "Desired State";
        var parts = code.Split('.');
        if (parts.Length >= 2 && string.Equals(parts[0], "DesiredState", StringComparison.OrdinalIgnoreCase)) {
            return parts[1];
        }
        return "Desired State";
    }

    private static RecommendationDomain MapDomain(string area) {
        if (string.IsNullOrWhiteSpace(area)) return RecommendationDomain.Other;
        switch (area.ToUpperInvariant()) {
            case "SPF": return RecommendationDomain.Spf;
            case "DKIM": return RecommendationDomain.Dkim;
            case "DMARC": return RecommendationDomain.Dmarc;
            case "DNSSEC": return RecommendationDomain.Dnssec;
            case "TLSRPT":
            case "STARTTLS":
            case "SMTPTLS":
            case "IMAPTLS":
            case "POP3TLS":
            case "MAILTLS":
                return RecommendationDomain.Tls;
            case "MTASTS":
            case "TLSRPTREPORTS":
            case "MX":
                return RecommendationDomain.EmailAuth;
            case "HTTP":
                return RecommendationDomain.Http;
            case "DNSBL":
            case "RPKI":
            case "EDNSSUPPORT":
            case "DNSOVERTLS":
            case "DNSHEALTH":
            case "DELEGATION":
            case "ZONETRANSFER":
            case "WILDCARDDNS":
            case "APEXADDRESS":
                return RecommendationDomain.Infrastructure;
            default:
                return RecommendationDomain.Other;
        }
    }
}

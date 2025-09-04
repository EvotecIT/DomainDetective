using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class SmimeaRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[SmimeaCodes.NoRecords] = new RecommendationAdvice {
            Code = SmimeaCodes.NoRecords,
            Title = "No SMIMEA records found",
            Why = "Without SMIMEA, recipients cannot validate S/MIME certificates via DNSSEC.",
            How = "Publish SMIMEA records at _smimecert.<local-part>.<domain> with correct usage/selector/matching semantics.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc8162" },
            Domain = RecommendationDomain.Privacy,
            Tags = new [] { "smimea", "dnssec" },
            Impact = "Recipients may not trust S/MIME signatures for your domain.",
            Effort = RecommendationEffort.Medium,
            Verify = "dig <hash>._smimecert.<domain> SMIMEA and check records exist."
        };

        map[SmimeaCodes.HostInvalid] = new RecommendationAdvice {
            Code = SmimeaCodes.HostInvalid,
            Title = "Invalid SMIMEA host name",
            Why = "Incorrect owner name prevents clients from locating the certificate association.",
            How = "Use the local-part label with _smimecert prefix per RFC 8162.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc8162#section-4" },
            Domain = RecommendationDomain.Privacy,
            Tags = new [] { "smimea" },
            Impact = "SMIMEA lookups fail.",
            Effort = RecommendationEffort.Low,
            Verify = "Confirm owner name matches <hash>._smimecert.<domain>."
        };

        map[SmimeaCodes.RecordPresent] = new RecommendationAdvice {
            Code = SmimeaCodes.RecordPresent,
            Title = "SMIMEA record present",
            Why = "Publishing SMIMEA enables DNSSEC-backed discovery of S/MIME certificates.",
            How = "Maintain SMIMEA records for addresses that use S/MIME.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc8162" },
            Domain = RecommendationDomain.Privacy,
            Tags = new [] { "smimea" }
        };

        map[SmimeaCodes.CertificateValid] = new RecommendationAdvice {
            Code = SmimeaCodes.CertificateValid,
            Title = "Valid S/MIME certificate association",
            Why = "Correct usage, selector, and matching type allow clients to verify certificates.",
            How = "Continue renewing and monitoring published S/MIME certificates.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc8162" },
            Domain = RecommendationDomain.Privacy,
            Tags = new [] { "smimea", "certificate" }
        };
    }
}


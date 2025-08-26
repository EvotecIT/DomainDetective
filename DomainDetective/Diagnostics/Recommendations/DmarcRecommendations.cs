using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class DmarcRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[DmarcCodes.AlignmentInvalid] = new RecommendationAdvice {
            Code = DmarcCodes.AlignmentInvalid,
            Title = "Invalid DMARC alignment value",
            Why = "Incorrect 'adkim'/'aspf' values can be ignored or degrade enforcement.",
            How = "Use 'r' (relaxed) or 's' (strict) for 'adkim' and 'aspf'. Align DKIM signing domain and/or SPF envelope-from with the From domain.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc7489" },
            Domain = RecommendationDomain.Dmarc,
            Tags = new [] { "dmarc" },
            Impact = "Receivers may ignore your intended alignment policy.",
            Effort = RecommendationEffort.Low,
            Verify = "Check DMARC record for 'adkim'/'aspf' values are r or s."
        };

        map[DmarcCodes.AlignmentMismatch] = new RecommendationAdvice {
            Code = DmarcCodes.AlignmentMismatch,
            Title = "DMARC alignment mismatch",
            Why = "Messages that do not align on DKIM or SPF will fail DMARC when policy is enforced.",
            How = "Ensure DKIM signs with a domain aligned to the From domain and/or SPF uses an aligned envelope-from. Adjust 'adkim'/'aspf' as needed.",
            Links = new [] { "https://dmarc.org/resources/overview/" },
            Domain = RecommendationDomain.Dmarc,
            Tags = new [] { "dmarc", "alignment" },
            Impact = "DMARC failures reduce deliverability and enable spoofing.",
            Effort = RecommendationEffort.Medium,
            Verify = "Inspect Authentication-Results headers for aligned DKIM/SPF on test mail."
        };

        map[DmarcCodes.UriInvalid] = new RecommendationAdvice {
            Code = DmarcCodes.UriInvalid,
            Title = "Invalid DMARC report URI",
            Why = "Receivers cannot send aggregate/forensic reports to invalid URIs.",
            How = "Use valid 'mailto:' URIs for 'rua'/'ruf'. Verify mailbox capacity and that external reporting is authorized if using a third party.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc7489#section-7.1" },
            Domain = RecommendationDomain.Dmarc,
            Tags = new [] { "dmarc", "reporting" },
            Impact = "Lose visibility into DMARC pass/fail across receivers.",
            Effort = RecommendationEffort.Low,
            Verify = "Confirm 'rua'/'ruf' use mailto: with valid addresses."
        };

        map[DmarcCodes.UriMissingScheme] = new RecommendationAdvice {
            Code = DmarcCodes.UriMissingScheme,
            Title = "DMARC report URI missing scheme",
            Why = "Without 'mailto:' scheme receivers may reject reporting destinations.",
            How = "Prefix report addresses with 'mailto:'. For multiple recipients, separate with commas.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc7489#section-7.1" },
            Domain = RecommendationDomain.Dmarc,
            Tags = new [] { "dmarc", "reporting" }
        };

        map[DmarcCodes.UriInsecure] = new RecommendationAdvice {
            Code = DmarcCodes.UriInsecure,
            Title = "Insecure reporting endpoint",
            Why = "Unencrypted transports or untrusted endpoints risk exposure of report data.",
            How = "Use trusted mailboxes for 'rua'/'ruf' (mailto). If using HTTP relay for processing, ensure TLS and access controls.",
            Links = new [] { "https://dmarc.org/resources/specifications/" },
            Domain = RecommendationDomain.Dmarc,
            Tags = new [] { "dmarc", "security" }
        };

        map[DmarcCodes.ReportingIntervalInvalid] = new RecommendationAdvice {
            Code = DmarcCodes.ReportingIntervalInvalid,
            Title = "Invalid DMARC reporting interval",
            Why = "Non-numeric or out-of-range 'ri' values may be ignored by receivers.",
            How = "Set 'ri' to a positive integer (seconds). Common values are 86400 (24h).",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc7489#section-6.3" },
            Domain = RecommendationDomain.Dmarc,
            Tags = new [] { "dmarc", "reporting" }
        };

        map[DmarcCodes.ReportingIntervalZeroOrNegative] = new RecommendationAdvice {
            Code = DmarcCodes.ReportingIntervalZeroOrNegative,
            Title = "DMARC reporting interval must be positive",
            Why = "Zero or negative intervals are invalid and may disable reporting.",
            How = "Use a positive 'ri' value, e.g., 86400 (24h).",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc7489#section-6.3" },
            Domain = RecommendationDomain.Dmarc,
            Tags = new [] { "dmarc" }
        };

        map[DmarcCodes.RufTooLarge] = new RecommendationAdvice {
            Code = DmarcCodes.RufTooLarge,
            Title = "Too many forensic report recipients",
            Why = "Multiple 'ruf' recipients can overload receivers and expose sensitive data.",
            How = "Reduce 'ruf' recipients, prefer aggregate 'rua' reporting, and ensure data handling aligns with privacy requirements.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc7489" },
            Domain = RecommendationDomain.Dmarc,
            Tags = new [] { "dmarc", "privacy" }
        };

        map[DmarcCodes.TagDeprecated] = new RecommendationAdvice {
            Code = DmarcCodes.TagDeprecated,
            Title = "Deprecated/unknown DMARC tag",
            Why = "Unsupported tags may be ignored and cause confusion or misconfiguration.",
            How = "Remove deprecated tags and keep only standard tags (v, p, rua, ruf, fo, adkim, aspf, sp, pct, ri).",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc7489" },
            Domain = RecommendationDomain.Dmarc,
            Tags = new [] { "dmarc" }
        };
    }
}

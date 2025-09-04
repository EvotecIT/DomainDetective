using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class DmarcRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[DmarcCodes.MissingRecord] = new RecommendationAdvice {
            Code = DmarcCodes.MissingRecord,
            Title = "Publish a DMARC record",
            Why = "Without DMARC, receivers cannot enforce or report alignment, enabling spoofing and reducing visibility.",
            How = "Add a TXT record at _dmarc.example.com with v=DMARC1; start with p=none and rua= for monitoring, then move to quarantine/reject.",
            Links = new [] { "https://dmarc.org/resources/" },
            Domain = RecommendationDomain.Dmarc,
            Tags = new [] { "dmarc", "dns" },
            Impact = "Higher spoofing risk and reduced deliverability control.",
            Effort = RecommendationEffort.Medium,
            Verify = "dig TXT _dmarc.example.com shows a single v=DMARC1 policy."
        };

        map[DmarcCodes.MultipleRecords] = new RecommendationAdvice {
            Code = DmarcCodes.MultipleRecords,
            Title = "Consolidate DMARC into a single record",
            Why = "Multiple DMARC records are not well-defined and can be ignored or cause inconsistent behavior.",
            How = "Merge tags into one v=DMARC1 string and remove duplicates.",
            Domain = RecommendationDomain.Dmarc,
            Tags = new [] { "dmarc" },
            Impact = "Policy may not be applied by receivers.",
            Effort = RecommendationEffort.Low,
            Verify = "Only one TXT at _dmarc.example.com remains."
        };

        map[DmarcCodes.StartsInvalid] = new RecommendationAdvice {
            Code = DmarcCodes.StartsInvalid,
            Title = "Fix DMARC version tag",
            Why = "DMARC records must begin with v=DMARC1 to be recognized.",
            How = "Ensure the record starts with v=DMARC1 and contains valid tags (p, rua, ruf, fo, adkim, aspf, sp, pct, ri).",
            Domain = RecommendationDomain.Dmarc,
            Tags = new [] { "dmarc" },
            Impact = "Policy ignored by receivers.",
            Effort = RecommendationEffort.Low,
            Verify = "Record starts with v=DMARC1."
        };

        map[DmarcCodes.RecordLengthExceeds] = new RecommendationAdvice {
            Code = DmarcCodes.RecordLengthExceeds,
            Title = "Reduce DMARC TXT size",
            Why = "Oversized TXT records risk truncation and parsing issues.",
            How = "Shorten URIs, reduce recipients, and keep chunks ≤255 bytes.",
            Domain = RecommendationDomain.Dmarc,
            Tags = new [] { "dmarc", "dns" },
            Impact = "Receivers may fail to parse policy.",
            Effort = RecommendationEffort.Low,
            Verify = "Each TXT chunk ≤255 chars; total comfortably under UDP limits."
        };

        map[DmarcCodes.QueryFailed] = new RecommendationAdvice {
            Code = DmarcCodes.QueryFailed,
            Title = "DMARC DNS query failed",
            Why = "Transient DNS issues can prevent DMARC validation.",
            How = "Retry with different resolver/endpoints or increase timeout; confirm network egress.",
            Domain = RecommendationDomain.Dmarc,
            Tags = new [] { "dmarc", "dns" },
            Effort = RecommendationEffort.Low,
            Verify = "Re-run TXT lookup for _dmarc.example.com successfully."
        };
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

        map[DmarcCodes.PolicyReject] = new RecommendationAdvice {
            Code = DmarcCodes.PolicyReject,
            Title = "DMARC policy set to reject",
            Why = "Reject policy blocks unauthenticated mail and prevents spoofing.",
            How = "Maintain p=reject so fraudulent messages are discarded.",
            Domain = RecommendationDomain.Dmarc,
            Tags = new [] { "dmarc", "policy" },
            Impact = "Receivers will reject mail that fails DMARC.",
            Effort = RecommendationEffort.Low,
            Links = new [] { "https://dmarc.org/resources/" },
            Verify = "DMARC record contains p=reject."
        };

        map[DmarcCodes.PolicyQuarantine] = new RecommendationAdvice {
            Code = DmarcCodes.PolicyQuarantine,
            Title = "DMARC policy set to quarantine",
            Why = "Quarantine policy directs unauthenticated mail to spam folders.",
            How = "Maintain p=quarantine to isolate suspicious messages.",
            Domain = RecommendationDomain.Dmarc,
            Tags = new [] { "dmarc", "policy" },
            Impact = "Spoofed mail is quarantined by receivers.",
            Effort = RecommendationEffort.Low,
            Links = new [] { "https://dmarc.org/resources/" },
            Verify = "DMARC record contains p=quarantine."
        };

        map[DmarcCodes.AlignmentStrictDkim] = new RecommendationAdvice {
            Code = DmarcCodes.AlignmentStrictDkim,
            Title = "Strict DKIM alignment enforced",
            Why = "adkim=s requires DKIM d= to exactly match the From domain.",
            How = "Keep adkim=s and sign messages with aligned DKIM domains.",
            Domain = RecommendationDomain.Dmarc,
            Tags = new [] { "dmarc", "alignment" },
            Impact = "Mitigates spoofing by enforcing domain match on DKIM.",
            Effort = RecommendationEffort.Low,
            Links = new [] { "https://dmarc.org/resources/overview/" },
            Verify = "DMARC record shows adkim=s."
        };

        map[DmarcCodes.AlignmentStrictSpf] = new RecommendationAdvice {
            Code = DmarcCodes.AlignmentStrictSpf,
            Title = "Strict SPF alignment enforced",
            Why = "aspf=s requires the MAIL FROM domain to exactly match the From domain.",
            How = "Keep aspf=s and align envelope-from with the From domain.",
            Domain = RecommendationDomain.Dmarc,
            Tags = new [] { "dmarc", "alignment" },
            Impact = "Ensures SPF-authenticated mail uses the same domain as From.",
            Effort = RecommendationEffort.Low,
            Links = new [] { "https://dmarc.org/resources/overview/" },
            Verify = "DMARC record shows aspf=s."
        };

        map[DmarcCodes.RuaPresent] = new RecommendationAdvice {
            Code = DmarcCodes.RuaPresent,
            Title = "Aggregate reporting address configured",
            Why = "rua= receives aggregate DMARC reports for visibility.",
            How = "Monitor the rua mailbox and adjust addresses as needed.",
            Domain = RecommendationDomain.Dmarc,
            Tags = new [] { "dmarc", "reporting" },
            Impact = "Enables visibility into overall DMARC performance.",
            Effort = RecommendationEffort.Low,
            Links = new [] { "https://dmarc.org/resources/" },
            Verify = "DMARC record contains a rua=mailto: address."
        };

        map[DmarcCodes.RufPresent] = new RecommendationAdvice {
            Code = DmarcCodes.RufPresent,
            Title = "Forensic reporting address configured",
            Why = "ruf= receives detailed failure reports for investigation.",
            How = "Monitor the ruf mailbox and handle sensitive data appropriately.",
            Domain = RecommendationDomain.Dmarc,
            Tags = new [] { "dmarc", "reporting" },
            Impact = "Provides granular insight into individual DMARC failures.",
            Effort = RecommendationEffort.Low,
            Links = new [] { "https://dmarc.org/resources/" },
            Verify = "DMARC record contains a ruf=mailto: address."
        };
    }
}

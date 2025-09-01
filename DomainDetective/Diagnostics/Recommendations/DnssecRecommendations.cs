using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class DnssecRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[DnssecCodes.RrsigExpiring] = new RecommendationAdvice {
            Code = DnssecCodes.RrsigExpiring,
            Title = "DNSSEC signatures are expiring",
            Why = "Expired RRSIGs cause DNSSEC validation failures and domain resolution issues for validating resolvers.",
            How = "Ensure regular signing and ZSK/KSK rollover. Automate resigning and monitor expiration windows.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc4035" },
            Domain = RecommendationDomain.Dnssec,
            Tags = new [] { "dnssec" },
            Impact = "Validating resolvers may fail to resolve your domain.",
            Effort = RecommendationEffort.Medium,
            Verify = "Check RRSIG expiration dates via dig; confirm resigning cron or KSK/ZSK rollover."
        };

        map[DnssecCodes.RootAnchorExpired] = new RecommendationAdvice {
            Code = DnssecCodes.RootAnchorExpired,
            Title = "Root trust anchor expired",
            Why = "Outdated trust anchors break DNSSEC chain of trust.",
            How = "Update validating resolvers with the current IANA root KSK trust anchor.",
            Links = new [] { "https://www.iana.org/dnssec/files" },
            Domain = RecommendationDomain.Dnssec,
            Tags = new [] { "dnssec", "infrastructure" }
        };

        map[DnssecCodes.RootAnchorExpiring] = new RecommendationAdvice {
            Code = DnssecCodes.RootAnchorExpiring,
            Title = "Root trust anchor expiring soon",
            Why = "Impending expiration risks DNSSEC validation failures.",
            How = "Schedule an update for resolvers to include the latest root DS and KSK.",
            Links = new [] { "https://www.iana.org/dnssec" },
            Domain = RecommendationDomain.Dnssec,
            Tags = new [] { "dnssec" }
        };

        map[DnssecCodes.DsDigestLengthUnexpected] = new RecommendationAdvice {
            Code = DnssecCodes.DsDigestLengthUnexpected,
            Title = "Unexpected DS digest length",
            Why = "Mismatched digest length suggests the wrong algorithm or malformed DS, breaking validation.",
            How = "Publish DS using recommended algorithms (e.g., SHA-256) with correct digest length.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc4509" },
            Domain = RecommendationDomain.Dnssec,
            Tags = new [] { "dnssec" }
        };

        map[DnssecCodes.DsAlgorithmUnknown] = new RecommendationAdvice {
            Code = DnssecCodes.DsAlgorithmUnknown,
            Title = "Unknown DS algorithm",
            Why = "Unsupported DS algorithms may be ignored by validators.",
            How = "Use widely supported DS algorithms (e.g., 2 = SHA-256).",
            Links = new [] { "https://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml" },
            Domain = RecommendationDomain.Dnssec,
            Tags = new [] { "dnssec" }
        };

        map[DnssecCodes.DsAlgorithmDeprecated] = new RecommendationAdvice {
            Code = DnssecCodes.DsAlgorithmDeprecated,
            Title = "Deprecated DS algorithm",
            Why = "Deprecated algorithms reduce security and compatibility.",
            How = "Migrate to SHA-256 DS and roll keys while keeping continuity.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc4509" },
            Domain = RecommendationDomain.Dnssec,
            Tags = new [] { "dnssec" }
        };

        map[DnssecCodes.DnskeyNotAuthenticated] = new RecommendationAdvice {
            Code = DnssecCodes.DnskeyNotAuthenticated,
            Title = "DNSKEY RRset not authenticated",
            Why = "Without authenticated DNSKEY, validators cannot build a trust chain for your zone.",
            How = "Ensure authoritative servers sign DNSKEY RRset and provide valid RRSIGs; check key publishing and rolling procedures.",
            Domain = RecommendationDomain.Dnssec,
            Tags = new [] { "dnssec" }
        };
        map[DnssecCodes.DsMissing] = new RecommendationAdvice {
            Code = DnssecCodes.DsMissing,
            Title = "Missing DS at parent",
            Why = "Without a DS record in the parent zone, DNSSEC validation cannot succeed.",
            How = "Publish a DS record for your zone at the parent registry; coordinate with your registrar.",
            Domain = RecommendationDomain.Dnssec,
            Tags = new [] { "dnssec" }
        };
        map[DnssecCodes.DsNotAuthenticated] = new RecommendationAdvice {
            Code = DnssecCodes.DsNotAuthenticated,
            Title = "DS not authenticated",
            Why = "Unauthenticated DS indicates broken chain of trust at the parent.",
            How = "Investigate parent zone signing; ensure DS RRSIGs are valid and resolvers see AD flag.",
            Domain = RecommendationDomain.Dnssec,
            Tags = new [] { "dnssec" }
        };
        map[DnssecCodes.DsMismatch] = new RecommendationAdvice {
            Code = DnssecCodes.DsMismatch,
            Title = "DS does not match DNSKEY",
            Why = "Mismatched DS prevents validators from trusting your zone keys.",
            How = "Update DS at the parent to match current KSK, or roll keys properly to avoid mismatch.",
            Domain = RecommendationDomain.Dnssec,
            Tags = new [] { "dnssec" }
        };

        map[DnssecCodes.Nsec3OptOutRisk] = new RecommendationAdvice {
            Code = DnssecCodes.Nsec3OptOutRisk,
            Title = "NSEC3 Opt-Out reduces DNSSEC coverage",
            Why = "Opt-Out allows unsigned delegations inside a signed zone, weakening protection for non-existent names and delegations.",
            How = "Disable Opt-Out where possible or ensure unsigned delegations are intended and low risk. Consider NSEC or NSEC3 without Opt-Out.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc5155" },
            Domain = RecommendationDomain.Dnssec,
            Tags = new [] { "dnssec", "nsec3" },
            Impact = "Increased risk of certain attack classes and reduced assurance for negative answers.",
            Effort = RecommendationEffort.Medium,
            Verify = "Query NSEC3PARAM/NSEC3; Flags should be 0 when Opt-Out is not used."
        };
    }
}

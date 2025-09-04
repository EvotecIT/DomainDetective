using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class TyposquattingRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[TyposquattingCodes.ContainsHomoglyphs] = new RecommendationAdvice {
            Code = TyposquattingCodes.ContainsHomoglyphs,
            Title = "Domain contains homoglyph characters",
            Why = "Homoglyphs can confuse users and increase impersonation risks.",
            How = "Prefer ASCII labels where possible; register common variants and monitor lookalikes.",
            Domain = RecommendationDomain.Branding,
            Tags = new [] { "homoglyphs", "impersonation" },
            Impact = "User confusion and phishing susceptibility.",
            Effort = RecommendationEffort.Medium,
            Verify = "Review registration strategy; ensure critical variants are secured."
        };

        map[TyposquattingCodes.VariantActive] = new RecommendationAdvice {
            Code = TyposquattingCodes.VariantActive,
            Title = "Active typosquat variant detected",
            Why = "A confusingly similar domain resolves and may be used for impersonation.",
            How = "Consider defensive registration, takedown, or blocklist with mail/web providers. Increase user training and DMARC enforcement.",
            Domain = RecommendationDomain.Branding,
            Tags = new [] { "typosquat", "impersonation" },
            Impact = "Fraud and brand abuse risks.",
            Effort = RecommendationEffort.High,
            Verify = "Confirm control or takedown of the variant domain."
        };

        map[TyposquattingCodes.VariantNone] = new RecommendationAdvice {
            Code = TyposquattingCodes.VariantNone,
            Title = "No active typosquat variants detected",
            Why = "No look-alike domains resolved in DNS during analysis.",
            How = "Continue monitoring for new registrations and maintain defensive strategy.",
            Domain = RecommendationDomain.Branding,
            Tags = new [] { "typosquat" },
            Impact = "Low current risk from typosquatting.",
            Effort = RecommendationEffort.Low,
            Verify = "Run periodic scans for emerging variants."
        };

        map[TyposquattingCodes.DefensiveRegistered] = new RecommendationAdvice {
            Code = TyposquattingCodes.DefensiveRegistered,
            Title = "Defensive typosquat domains registered",
            Why = "Registered variants reduce the chance of malicious use by third parties.",
            How = "Maintain control and renew these domains as part of brand protection.",
            Domain = RecommendationDomain.Branding,
            Tags = new [] { "typosquat", "defensive" },
            Impact = "Helps prevent brand abuse.",
            Effort = RecommendationEffort.Low,
            Verify = "Ensure the domains remain under your ownership."
        };
    }
}


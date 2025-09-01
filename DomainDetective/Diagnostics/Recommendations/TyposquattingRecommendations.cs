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
    }
}


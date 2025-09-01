using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class ThreatIntelRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[ThreatIntelCodes.VirusTotalRiskHigh] = new RecommendationAdvice {
            Code = ThreatIntelCodes.VirusTotalRiskHigh,
            Title = "High VirusTotal risk score",
            Why = "Public reputation feeds flag the domain/IP; this can affect deliverability and user trust.",
            How = "Investigate malicious content, phishing reports, and recent changes. Remediate, then request re-evaluation at the respective services.",
            Links = new [] { "https://www.virustotal.com/gui/home/search" },
            Domain = RecommendationDomain.ThreatIntel,
            Tags = new [] { "reputation" }
        };
    }
}


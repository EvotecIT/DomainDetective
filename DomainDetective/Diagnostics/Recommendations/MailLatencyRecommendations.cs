using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class MailLatencyRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[MailLatencyCodes.ConnectUnderThreshold] = new RecommendationAdvice {
            Code = MailLatencyCodes.ConnectUnderThreshold,
            Title = "Connection latency within acceptable threshold",
            Why = "Fast connections improve reliability and user experience.",
            How = "No action required; maintain current network performance.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "smtp", "latency" },
            Effort = RecommendationEffort.Low,
            Verify = "Periodically test latency to ensure continued responsiveness."
        };

        map[MailLatencyCodes.BannerUnderThreshold] = new RecommendationAdvice {
            Code = MailLatencyCodes.BannerUnderThreshold,
            Title = "Banner latency within acceptable threshold",
            Why = "Prompt banners indicate responsive mail servers.",
            How = "No action required; maintain server responsiveness.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "smtp", "latency" },
            Effort = RecommendationEffort.Low,
            Verify = "Periodically test latency to ensure continued responsiveness."
        };
    }
}

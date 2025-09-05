using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class MailLatencyRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[MailLatencyCodes.ConnectFast] = new RecommendationAdvice {
            Code = MailLatencyCodes.ConnectFast,
            Title = "SMTP connection latency within threshold",
            Why = "Quick server responses improve mail flow and diagnostics.",
            How = "No action required.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "smtp", "latency" },
            Impact = "Indicates responsive mail server.",
            Effort = RecommendationEffort.Low,
            Verify = "Measure connection latency periodically."
        };

        map[MailLatencyCodes.BannerFast] = new RecommendationAdvice {
            Code = MailLatencyCodes.BannerFast,
            Title = "SMTP banner latency within threshold",
            Why = "Prompt banner delivery confirms responsive SMTP software.",
            How = "No action required.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "smtp", "latency" },
            Impact = "Shows minimal post-connect delay.",
            Effort = RecommendationEffort.Low,
            Verify = "Measure banner latency periodically."
        };
    }
}

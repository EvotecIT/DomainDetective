using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class NtpRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[NtpCodes.ReasonableOffset] = new RecommendationAdvice {
            Code = NtpCodes.ReasonableOffset,
            Title = "Clock offset within acceptable range",
            Why = "Small time offsets keep logs and security protocols reliable.",
            How = "Ensure systems sync with reliable NTP servers and monitor drift.",
            Links = new [] { "https://datatracker.ietf.org/doc/html/rfc5905" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "ntp", "time" }
        };

        map[NtpCodes.TrustedStratum] = new RecommendationAdvice {
            Code = NtpCodes.TrustedStratum,
            Title = "NTP server reports trusted stratum",
            Why = "Low stratum values indicate proximity to authoritative time sources.",
            How = "Use servers with stratum 1-4 or reputable public pools.",
            Links = new [] { "https://datatracker.ietf.org/doc/html/rfc5905" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "ntp", "time" }
        };
    }
}


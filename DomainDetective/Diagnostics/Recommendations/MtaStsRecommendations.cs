using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class MtaStsRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[MtaStsCodes.FetchFailed] = new RecommendationAdvice {
            Code = MtaStsCodes.FetchFailed,
            Title = "MTA-STS policy not reachable",
            Why = "Without a valid MTA-STS policy, SMTP TLS is opportunistic and downgrade attacks are possible.",
            How = "Host policy at https://mta-sts.<domain>/.well-known/mta-sts.txt with 'mode', 'max_age', and 'mx' entries; ensure valid TLS on host.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc8461" },
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "mta-sts" }
        };
    }
}


using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class ApexAddressRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[ApexAddressCodes.PubliclyRoutable] = new RecommendationAdvice {
            Code = ApexAddressCodes.PubliclyRoutable,
            Title = "Apex addresses are publicly routable",
            Why = "Publicly routable A/AAAA records allow external services to reach your domain.",
            How = "Keep apex A/AAAA records on globally reachable IP addresses.",
            Links = new[] { "https://www.rfc-editor.org/rfc/rfc6890" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "dns", "apex", "ip" }
        };

        map[ApexAddressCodes.FcrDnsValid] = new RecommendationAdvice {
            Code = ApexAddressCodes.FcrDnsValid,
            Title = "Apex addresses have forward-confirmed reverse DNS",
            Why = "FCrDNS improves deliverability and trust by ensuring PTR names resolve back to their IPs.",
            How = "Publish PTR records whose hostnames contain A/AAAA records pointing back to the originating IPs.",
            Links = new[] { "https://www.rfc-editor.org/rfc/rfc1912#section-2.1" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "dns", "ptr", "fcrdns" }
        };
    }
}

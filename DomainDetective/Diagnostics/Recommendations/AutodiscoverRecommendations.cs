using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class AutodiscoverRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[AutodiscoverCodes.CheckFailed] = new RecommendationAdvice {
            Code = AutodiscoverCodes.CheckFailed,
            Title = "Autodiscover check failed",
            Why = "Network or protocol error prevented Autodiscover validation.",
            How = "Verify endpoint availability and TLS; retry from a known-good vantage point.",
            Domain = RecommendationDomain.EmailAuth,
            Tags = new [] { "autodiscover", "http" },
            Impact = "Uncertain posture; manual validation required.",
            Effort = RecommendationEffort.Low,
            Verify = "Re-run Autodiscover HTTP checks and confirm status 200 with valid XML/JSON."
        };
        map[AutodiscoverCodes.MissingSrv] = new RecommendationAdvice {
            Code = AutodiscoverCodes.MissingSrv,
            Title = "Publish _autodiscover._tcp SRV record",
            Why = "An SRV record can guide clients to the correct Autodiscover endpoint.",
            How = "Add an SRV record: _autodiscover._tcp IN SRV 0 0 443 autodiscover.example.com.",
            Domain = RecommendationDomain.EmailAuth,
            Tags = new [] { "autodiscover", "dns", "srv" },
            Impact = "Clients may fail to locate Autodiscover automatically.",
            Effort = RecommendationEffort.Low,
            Verify = "Query _autodiscover._tcp.<domain> SRV and confirm target/port."
        };
        map[AutodiscoverCodes.BadSrvTarget] = new RecommendationAdvice {
            Code = AutodiscoverCodes.BadSrvTarget,
            Title = "Fix SRV target host",
            Why = "SRV should point at a valid hostname serving Autodiscover.",
            How = "Set the SRV target to a resolvable host that responds on HTTPS 443.",
            Domain = RecommendationDomain.EmailAuth,
            Tags = new [] { "autodiscover", "dns", "srv" },
            Impact = "Autodiscover resolution may fail.",
            Effort = RecommendationEffort.Low,
            Verify = "SRV target resolves and serves Autodiscover over HTTPS."
        };
        map[AutodiscoverCodes.MissingAutoconfigCname] = new RecommendationAdvice {
            Code = AutodiscoverCodes.MissingAutoconfigCname,
            Title = "Optionally add autoconfig CNAME",
            Why = "Some clients consult autoconfig.<domain> for discovery.",
            How = "Create CNAME autoconfig.<domain> to vendor or service endpoint when applicable.",
            Domain = RecommendationDomain.EmailAuth,
            Tags = new [] { "autodiscover", "dns", "cname" },
            Impact = "Some clients may need manual config.",
            Effort = RecommendationEffort.Low,
            Verify = "CNAME resolves to a valid Autoconfig endpoint."
        };
        map[AutodiscoverCodes.MissingAutodiscoverCname] = new RecommendationAdvice {
            Code = AutodiscoverCodes.MissingAutodiscoverCname,
            Title = "Publish autodiscover CNAME or A/AAAA",
            Why = "autodiscover.<domain> is commonly used by clients for discovery.",
            How = "Create CNAME autodiscover.<domain> → service endpoint or provide A/AAAA records.",
            Domain = RecommendationDomain.EmailAuth,
            Tags = new [] { "autodiscover", "dns", "cname" },
            Impact = "Clients may not find the service automatically.",
            Effort = RecommendationEffort.Low,
            Verify = "Lookup returns a valid target that serves Autodiscover."
        };
        map[AutodiscoverCodes.BadAutoconfigTarget] = new RecommendationAdvice {
            Code = AutodiscoverCodes.BadAutoconfigTarget,
            Title = "Fix autoconfig CNAME target",
            Why = "CNAME should reference a valid, resolvable host.",
            How = "Point autoconfig.<domain> to a valid vendor/service hostname.",
            Domain = RecommendationDomain.EmailAuth,
            Tags = new [] { "autodiscover", "dns" },
            Impact = "Autoconfig discovery may fail.",
            Effort = RecommendationEffort.Low,
            Verify = "CNAME target resolves and serves expected content."
        };
        map[AutodiscoverCodes.BadAutodiscoverTarget] = new RecommendationAdvice {
            Code = AutodiscoverCodes.BadAutodiscoverTarget,
            Title = "Fix autodiscover CNAME target",
            Why = "Target must be a valid Autodiscover endpoint.",
            How = "Update target to a resolvable endpoint that responds on 443.",
            Domain = RecommendationDomain.EmailAuth,
            Tags = new [] { "autodiscover", "dns" },
            Impact = "Client discovery may fail or misroute.",
            Effort = RecommendationEffort.Low,
            Verify = "Target resolves and validates over HTTPS."
        };
    }
}

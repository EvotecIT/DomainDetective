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
        map[AutodiscoverCodes.Office365FlowFailed] = new RecommendationAdvice {
            Code = AutodiscoverCodes.Office365FlowFailed,
            Title = "Office 365 Autodiscover redirected but HTTP flow failed",
            Why = "CNAME points to outlook.com indicating Microsoft 365, but the Autodiscover HTTP flow did not complete with valid XML.",
            How = "Allow HTTPS with SNI to outlook.com endpoints; disable TLS interception or captive portals; verify redirects reach autodiscover-s.outlook.com and return XML.",
            Domain = RecommendationDomain.EmailAuth,
            Tags = new [] { "autodiscover", "office365", "tls", "network" },
            Impact = "Outlook/clients may fail automatic configuration.",
            Effort = RecommendationEffort.Medium,
            Verify = "GET https://autodiscover.<domain>/autodiscover/autodiscover.xml follows redirects and returns Autodiscover XML (200)."
        };
        map[AutodiscoverCodes.EndpointDiscovered] = new RecommendationAdvice {
            Code = AutodiscoverCodes.EndpointDiscovered,
            Title = "Autodiscover endpoint discovered",
            Why = "A responsive Autodiscover service allows clients to configure automatically.",
            How = "Maintain DNS hints and HTTPS availability so clients continue to reach the service.",
            Domain = RecommendationDomain.EmailAuth,
            Tags = new [] { "autodiscover", "http" },
            Impact = "Improves user experience through automatic setup.",
            Effort = RecommendationEffort.Low,
            Verify = "Repeat Autodiscover check and confirm an endpoint responds successfully."
        };
        map[AutodiscoverCodes.XmlValid] = new RecommendationAdvice {
            Code = AutodiscoverCodes.XmlValid,
            Title = "Autodiscover XML response valid",
            Why = "Valid XML ensures clients obtain configuration without errors.",
            How = "Keep the Autodiscover implementation and TLS configuration up to date.",
            Domain = RecommendationDomain.EmailAuth,
            Tags = new [] { "autodiscover", "xml" },
            Impact = "Clients can securely retrieve settings.",
            Effort = RecommendationEffort.Low,
            Verify = "GET/POST Autodiscover endpoint returns XML root <Autodiscover> with expected namespace."
        };
        map[AutodiscoverCodes.JsonValid] = new RecommendationAdvice {
            Code = AutodiscoverCodes.JsonValid,
            Title = "Autodiscover JSON discovery succeeded",
            Why = "Outlook v2 JSON provided a valid Autodiscover endpoint.",
            How = "Ensure the Microsoft discovery service remains reachable over HTTPS.",
            Domain = RecommendationDomain.EmailAuth,
            Tags = new [] { "autodiscover", "json" },
            Impact = "Outlook clients have a fallback path for automatic configuration.",
            Effort = RecommendationEffort.Low,
            Verify = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.json/v1.0/<domain>?Protocol=AutodiscoverV1 returns endpoint URL."
        };
    }
}

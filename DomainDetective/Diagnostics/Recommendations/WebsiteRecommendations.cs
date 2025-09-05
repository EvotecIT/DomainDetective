using System.Collections.Generic;

namespace DomainDetective.Recommendations
{
    internal sealed class WebsiteRecommendations : IRecommendationProvider
    {
        public void Register(IDictionary<string, RecommendationAdvice> map)
        {
            if (!map.ContainsKey(HttpCodes.HstsPresent))
            {
                map[HttpCodes.HstsPresent] = new RecommendationAdvice
                {
                    Code = HttpCodes.HstsPresent,
                    Title = "HSTS enabled",
                    Why = "HSTS enforces HTTPS and mitigates downgrade attacks.",
                    How = "Maintain Strict-Transport-Security with adequate max-age and includeSubDomains when ready.",
                    Domain = RecommendationDomain.Http,
                    Tags = new[] { "hsts" },
                    Impact = "Improves transport security for browsers.",
                    Effort = RecommendationEffort.Low,
                    Verify = "Fetch a page and confirm the Strict-Transport-Security header."
                };
            }

            if (!map.ContainsKey(HttpCodes.CspPresent))
            {
                map[HttpCodes.CspPresent] = new RecommendationAdvice
                {
                    Code = HttpCodes.CspPresent,
                    Title = "Content Security Policy present",
                    Why = "CSP restricts sources of executable content and reduces XSS risk.",
                    How = "Keep a strict CSP using nonces or hashes and avoid unsafe directives.",
                    Domain = RecommendationDomain.Http,
                    Tags = new[] { "csp" },
                    Impact = "Hardens client-side security.",
                    Effort = RecommendationEffort.Medium,
                    Verify = "Inspect responses for the Content-Security-Policy header."
                };
            }

            if (!map.ContainsKey(TlsCodes.StrongProtocol))
            {
                map[TlsCodes.StrongProtocol] = new RecommendationAdvice
                {
                    Code = TlsCodes.StrongProtocol,
                    Title = "Modern TLS protocol negotiated",
                    Why = "TLS 1.2 or 1.3 provides strong, interoperable encryption.",
                    How = "Enable TLS 1.2 and 1.3 while disabling legacy protocols.",
                    Links = new[] { "https://datatracker.ietf.org/doc/rfc8996/" },
                    Domain = RecommendationDomain.Tls,
                    Tags = new[] { "tls" },
                    Impact = "Protects data in transit with robust ciphers.",
                    Effort = RecommendationEffort.Low,
                    Verify = "Confirm handshake negotiates TLS 1.2 or TLS 1.3."
                };
            }
        }
    }
}


using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class SubdomainRecommendations : IRecommendationProvider
{
    public void Register(IDictionary<string, RecommendationAdvice> map)
    {
        map[SubdomainCodes.SensitiveSubdomainsHigh] = new RecommendationAdvice
        {
            Code = SubdomainCodes.SensitiveSubdomainsHigh,
            Title = "Sensitive subdomains exposed (high risk)",
            Why = "Administrative/authentication endpoints are high-value targets and can enable credential attacks, phishing, or direct compromise.",
            How = "Review exposed subdomains, restrict access (VPN/IP allowlists), enforce MFA, and ensure strong TLS/security headers. Remove stale services.",
            Links = new[] { "https://owasp.org/www-project-web-security-testing-guide/" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "subdomain", "exposure", "attack-surface" },
            Impact = "Increased likelihood of account compromise and data exposure.",
            Effort = RecommendationEffort.Medium,
            Verify = "Confirm sensitive endpoints require authentication and are not exposed unintentionally."
        };

        map[SubdomainCodes.SensitiveSubdomainsModerate] = new RecommendationAdvice
        {
            Code = SubdomainCodes.SensitiveSubdomainsModerate,
            Title = "Sensitive subdomains exposed (moderate risk)",
            Why = "Development/staging/billing-related hostnames increase attacker focus and may have weaker controls than production.",
            How = "Ensure non-production hosts are protected (auth, allowlists), remove unused subdomains, and enforce consistent security controls.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "subdomain", "exposure" },
            Impact = "Higher likelihood of targeted probing and exploitation.",
            Effort = RecommendationEffort.Medium,
            Verify = "Validate each exposed hostname is intended and hardened."
        };

        map[SubdomainCodes.AiInfrastructureExposed] = new RecommendationAdvice
        {
            Code = SubdomainCodes.AiInfrastructureExposed,
            Title = "AI/ML infrastructure hostname exposed",
            Why = "AI/ML platforms (e.g., notebooks and workflow tools) are often high-value targets and may expose data, models, or credentials when publicly reachable.",
            How = "Review detected hostnames, restrict access (VPN/IP allowlists), require authentication/MFA, and ensure environments are patched and monitored.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "subdomain", "ai", "exposure" },
            Impact = "Increased likelihood of data/model leakage and service compromise.",
            Effort = RecommendationEffort.Medium,
            Verify = "Confirm AI/ML tooling is not exposed publicly unless intended and hardened."
        };

        map[SubdomainCodes.SensitiveTxtSuspicious] = new RecommendationAdvice
        {
            Code = SubdomainCodes.SensitiveTxtSuspicious,
            Title = "Suspicious TXT content on sensitive subdomains",
            Why = "Malicious actors can hide payloads or instructions in DNS TXT records for command-and-control or staging.",
            How = "Audit TXT records, remove unknown entries, rotate compromised secrets/tokens, and review DNS change history.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "dns", "txt", "malware" },
            Impact = "Potential covert channel or persistence mechanism.",
            Effort = RecommendationEffort.High,
            Verify = "Re-scan TXT records and confirm only expected values remain."
        };

        map[SubdomainCodes.NonPublicIpAddress] = new RecommendationAdvice
        {
            Code = SubdomainCodes.NonPublicIpAddress,
            Title = "Subdomain resolves to non-public IP address",
            Why = "Publishing private/loopback/link-local/ULA addresses in public DNS can enable DNS rebinding scenarios or leak internal topology.",
            How = "Remove non-public answers from public DNS, use split-horizon DNS correctly, and validate internal services are not exposed unintentionally.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "dns", "rebinding", "private-ip" },
            Impact = "Potential access to internal resources and information disclosure.",
            Effort = RecommendationEffort.Medium,
            Verify = "Resolve from public resolvers; answers should be publicly routable."
        };
    }
}

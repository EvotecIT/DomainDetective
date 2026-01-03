using System;
using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class DnsAmplificationRecommendations : IRecommendationProvider
{
    public void Register(IDictionary<string, RecommendationAdvice> map)
    {
        map[DnsAmplificationCodes.HighRisk] = new RecommendationAdvice
        {
            Code = DnsAmplificationCodes.HighRisk,
            Title = "Mitigate high DNS amplification risk",
            Why = "Open recursion combined with large UDP responses can enable reflection/amplification attacks.",
            How = "Disable recursion on authoritative servers, limit EDNS UDP payload to ~1232 bytes, and enable DNS response rate limiting (RRL) or equivalent protections at the DNS provider.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "dns", "amplification", "ddos", "edns", "recursion" },
            Impact = "Reduces the ability to abuse your DNS servers for reflection attacks and improves resilience.",
            Effort = RecommendationEffort.Medium,
            Verify = "Recursion probes return REFUSED (RA=0) and large-answer probes are truncated or bounded over UDP."
        };

        map[DnsAmplificationCodes.OpenRecursion] = new RecommendationAdvice
        {
            Code = DnsAmplificationCodes.OpenRecursion,
            Title = "Disable open recursion",
            Why = "Open resolvers can be abused for amplification attacks and cache poisoning.",
            How = "Restrict recursion to trusted networks or disable it entirely on authoritative name servers.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "dns", "recursion" },
            Impact = "Reduces amplification and cache-poisoning exposure.",
            Effort = RecommendationEffort.Low,
            Verify = "Queries for unrelated domains return REFUSED and RA is unset."
        };

        map[DnsAmplificationCodes.EdnsUdpPayloadTooLarge] = new RecommendationAdvice
        {
            Code = DnsAmplificationCodes.EdnsUdpPayloadTooLarge,
            Title = "Limit EDNS UDP payload size",
            Why = "Large UDP payload sizes increase fragmentation and can increase amplification potential.",
            How = "Configure authoritative DNS to advertise a smaller UDP payload size (commonly 1232) and ensure TCP fallback works.",
            Links = new[] { "https://www.rfc-editor.org/rfc/rfc8900" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "dns", "edns", "udp", "fragmentation" },
            Impact = "Improves reliability and reduces abuse potential for large UDP responses.",
            Effort = RecommendationEffort.Medium,
            Verify = "Server advertises <=1232 in OPT and large answers set TC=1 for UDP."
        };

        map[DnsAmplificationCodes.LargeUdpResponse] = new RecommendationAdvice
        {
            Code = DnsAmplificationCodes.LargeUdpResponse,
            Title = "Reduce large UDP DNS answers",
            Why = "Large UDP responses can contribute to reflection/amplification attacks.",
            How = "Enable RRL (or equivalent), avoid oversized records where possible, and consider limiting EDNS UDP payload sizes to reduce response amplification over UDP.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "dns", "ddos", "amplification", "rrl" },
            Impact = "Reduces the amplification factor available to attackers.",
            Effort = RecommendationEffort.Medium,
            Verify = "Large-answer probes are truncated over UDP (TC=1) or reduced in size."
        };

        map[DnsAmplificationCodes.NoIndicators] = new RecommendationAdvice
        {
            Code = DnsAmplificationCodes.NoIndicators,
            Title = "DNS amplification posture looks good",
            Why = "Recursion is not available and UDP answers appear bounded.",
            How = "No action required; maintain current protections and monitor for regressions.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "dns", "amplification" },
            Impact = "Reduced risk of DNS reflection abuse.",
            Effort = RecommendationEffort.Low,
            Verify = "Re-run the check periodically or after DNS provider changes."
        };

        map[DnsAmplificationCodes.CheckFailed] = new RecommendationAdvice
        {
            Code = DnsAmplificationCodes.CheckFailed,
            Title = "DNS amplification probe failed",
            Why = "Timeouts or errors may hide real exposure or indicate reachability/rate-limiting issues.",
            How = "Retry from a different network vantage point and verify UDP/53 reachability to authoritative name servers.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "dns", "amplification", "timeout" },
            Impact = "Unknown posture until validated.",
            Effort = RecommendationEffort.Low,
            Verify = "Repeat the probe and confirm stable responses."
        };

        map[DnsAmplificationCodes.NameServersMissing] = new RecommendationAdvice
        {
            Code = DnsAmplificationCodes.NameServersMissing,
            Title = "No name servers found",
            Why = "Without authoritative NS records, DNS posture checks cannot be performed.",
            How = "Verify the domain exists and has valid NS delegation.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "dns", "ns" },
            Impact = "Domain may be misconfigured or not resolvable.",
            Effort = RecommendationEffort.Low,
            Verify = "NS queries return authoritative servers for the domain."
        };

        map[DnsAmplificationCodes.NameServerAddressesMissing] = new RecommendationAdvice
        {
            Code = DnsAmplificationCodes.NameServerAddressesMissing,
            Title = "Name servers have no A/AAAA addresses",
            Why = "Amplification posture requires probing the authoritative server IPs.",
            How = "Ensure each NS hostname resolves to at least one A or AAAA record and that glue is configured where required.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "dns", "ns", "glue" },
            Impact = "Validation and resilience are reduced.",
            Effort = RecommendationEffort.Medium,
            Verify = "Each NS hostname resolves to reachable A/AAAA addresses."
        };
    }
}


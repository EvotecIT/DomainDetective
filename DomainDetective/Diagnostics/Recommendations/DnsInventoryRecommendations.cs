using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class DnsInventoryRecommendations : IRecommendationProvider
{
    public void Register(IDictionary<string, RecommendationAdvice> map)
    {
        map[DnsInventoryCodes.ApexAaaaMissing] = new RecommendationAdvice
        {
            Code = DnsInventoryCodes.ApexAaaaMissing,
            Title = "Apex AAAA record missing",
            Why = "Lack of an apex AAAA record can indicate incomplete IPv6 support. This may be intentional for domains used only for subdomains.",
            How = "If you intend to serve the apex over IPv6, publish an AAAA record at the zone apex. Otherwise, document that IPv6 is not supported at the apex.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "dns", "ipv6", "aaaa" },
            Impact = "IPv6-only clients may not reach the apex hostname.",
            Effort = RecommendationEffort.Low,
            Verify = "Query AAAA at the apex; it should return the intended IPv6 address."
        };

        map[DnsInventoryCodes.NonPublicIpAddress] = new RecommendationAdvice
        {
            Code = DnsInventoryCodes.NonPublicIpAddress,
            Title = "Non-public IP address returned in public DNS",
            Why = "Private/loopback/link-local/ULA addresses in public DNS can leak internal topology and enable DNS rebinding-style risks.",
            How = "Remove non-public answers from public DNS, use split-horizon DNS correctly, and validate internal services are not exposed via public resolvers.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "dns", "private-ip", "rebinding" },
            Impact = "Potential access to internal resources and information disclosure.",
            Effort = RecommendationEffort.Medium,
            Verify = "Resolve via public resolvers; answers should be publicly routable."
        };

        map[DnsInventoryCodes.TxtSuspiciousContent] = new RecommendationAdvice
        {
            Code = DnsInventoryCodes.TxtSuspiciousContent,
            Title = "Suspicious content detected in TXT/NULL records",
            Why = "Attackers sometimes abuse TXT (and rarely NULL) records to store payloads or command-and-control instructions.",
            How = "Audit TXT records for unknown values, remove suspicious entries, rotate any exposed secrets/tokens, and review DNS change history.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "dns", "txt", "null", "malware" },
            Impact = "Potential covert channel or persistence mechanism.",
            Effort = RecommendationEffort.High,
            Verify = "Re-scan TXT and confirm only expected values remain."
        };

        map[DnsInventoryCodes.TxtSignalsExposed] = new RecommendationAdvice
        {
            Code = DnsInventoryCodes.TxtSignalsExposed,
            Title = "Third-party verification/service tokens present in TXT",
            Why = "TXT records often contain site-verification and service ownership tokens; stale entries increase information disclosure and clutter.",
            How = "Review TXT records for unused third-party tokens (e.g., search verification) and remove those no longer needed. Prefer least-privilege and rotate tokens if compromise is suspected.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "dns", "txt", "verification" },
            Impact = "Increases recon signals and may expose internal tooling history.",
            Effort = RecommendationEffort.Low,
            Verify = "Re-query apex TXT and confirm only active/required tokens remain."
        };

        map[DnsInventoryCodes.ServiceDiscoveryExposed] = new RecommendationAdvice
        {
            Code = DnsInventoryCodes.ServiceDiscoveryExposed,
            Title = "Service discovery information exposed in DNS",
            Why = "Records like SRV/NAPTR/URI can reveal internal service topology and software choices.",
            How = "Keep service discovery records only where needed; remove stale entries and avoid exposing internal-only services via public DNS.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "dns", "srv", "naptr" },
            Impact = "Increases recon signal for attackers.",
            Effort = RecommendationEffort.Low,
            Verify = "Extended inventory shows only required service discovery records."
        };

        map[DnsInventoryCodes.Ipv6Incomplete] = new RecommendationAdvice
        {
            Code = DnsInventoryCodes.Ipv6Incomplete,
            Title = "Incomplete IPv6 support detected",
            Why = "IPv6 improves reachability for IPv6-only networks and helps future-proof DNS and mail infrastructure.",
            How = "Add AAAA records for the apex and ensure MX/NS hostnames also publish AAAA where supported by your providers.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "dns", "ipv6", "aaaa" },
            Impact = "Some networks may have reduced reachability or rely on translation.",
            Effort = RecommendationEffort.Medium,
            Verify = "Query AAAA for the apex, MX hosts, and NS hosts; confirm expected IPv6 answers."
        };
    }
}

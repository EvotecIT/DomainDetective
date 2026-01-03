using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class DnsOverTlsRecommendations : IRecommendationProvider
{
    public void Register(IDictionary<string, RecommendationAdvice> map)
    {
        map[DnsOverTlsCodes.NotSupported] = new RecommendationAdvice
        {
            Code = DnsOverTlsCodes.NotSupported,
            Title = "DNS over TLS not supported",
            Why = "DNS over TLS (DoT, RFC 7858) encrypts DNS queries in transit, improving privacy and making passive monitoring harder.",
            How = "If you operate a recursive resolver for users/clients, enable DoT (or DoH) and publish the resolver endpoint. For authoritative DNS, DoT support depends on your DNS provider; consider providers that offer encrypted DNS transports if this is a requirement.",
            Links = new[] { "https://www.rfc-editor.org/rfc/rfc7858" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "dns", "dot", "privacy", "tls" },
            Impact = "Improves DNS transport privacy for clients that use DoT.",
            Effort = RecommendationEffort.Medium,
            Verify = "Port 853 accepts TLS and DoT clients can complete a DNS exchange successfully."
        };

        map[DnsOverTlsCodes.Supported] = new RecommendationAdvice
        {
            Code = DnsOverTlsCodes.Supported,
            Title = "DNS over TLS supported",
            Why = "Encrypted DNS transport can improve privacy and reduce passive observation of DNS queries.",
            How = "Maintain your DoT configuration and monitor certificates/expiry to prevent outages.",
            Links = new[] { "https://www.rfc-editor.org/rfc/rfc7858" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "dns", "dot", "tls" },
            Impact = "Maintains encrypted DNS transport availability.",
            Effort = RecommendationEffort.Low,
            Verify = "Re-run the check periodically or after DNS provider changes."
        };

        map[DnsOverTlsCodes.CertificateMismatch] = new RecommendationAdvice
        {
            Code = DnsOverTlsCodes.CertificateMismatch,
            Title = "Fix DNS over TLS certificate hostname mismatch",
            Why = "DoT clients typically validate that the certificate matches the resolver hostname to prevent man-in-the-middle attacks.",
            How = "Install a certificate whose subject/SAN covers the DoT hostname and ensure the service is configured with the correct SNI/hostname.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "dns", "dot", "tls", "certificate" },
            Impact = "Improves interoperability with validating DoT clients.",
            Effort = RecommendationEffort.Medium,
            Verify = "TLS handshake succeeds and the certificate matches the resolver hostname."
        };

        map[DnsOverTlsCodes.CertificateInvalid] = new RecommendationAdvice
        {
            Code = DnsOverTlsCodes.CertificateInvalid,
            Title = "Fix invalid DNS over TLS certificate chain",
            Why = "Certificate validation failures can cause DoT clients to refuse connections.",
            How = "Use a publicly trusted certificate chain and renew before expiry; ensure intermediates are served correctly.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "dns", "dot", "tls", "certificate" },
            Impact = "Prevents DoT client failures caused by invalid certificates.",
            Effort = RecommendationEffort.Medium,
            Verify = "TLS handshake succeeds without certificate errors."
        };

        map[DnsOverTlsCodes.ProbeFailed] = new RecommendationAdvice
        {
            Code = DnsOverTlsCodes.ProbeFailed,
            Title = "DNS over TLS probe failed",
            Why = "Timeouts or network errors can hide real support or indicate reachability issues.",
            How = "Retry from a different network vantage point and verify TCP/853 reachability to authoritative name servers.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "dns", "dot", "timeout", "network" },
            Impact = "Unknown DoT posture until validated.",
            Effort = RecommendationEffort.Low,
            Verify = "Repeat the probe and confirm stable responses."
        };

        map[DnsOverTlsCodes.NameServersMissing] = new RecommendationAdvice
        {
            Code = DnsOverTlsCodes.NameServersMissing,
            Title = "No name servers found",
            Why = "Without authoritative NS records, DNS over TLS posture checks cannot be performed.",
            How = "Verify the domain exists and has valid NS delegation.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "dns", "ns" },
            Impact = "Domain may be misconfigured or not resolvable.",
            Effort = RecommendationEffort.Low,
            Verify = "NS queries return authoritative servers for the domain."
        };

        map[DnsOverTlsCodes.NameServerAddressesMissing] = new RecommendationAdvice
        {
            Code = DnsOverTlsCodes.NameServerAddressesMissing,
            Title = "Name servers have no A/AAAA addresses",
            Why = "DoT probing requires connecting to the authoritative server IPs.",
            How = "Ensure each NS hostname resolves to at least one A or AAAA record and that glue is configured where required.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "dns", "ns", "glue" },
            Impact = "Validation and resilience are reduced.",
            Effort = RecommendationEffort.Medium,
            Verify = "Each NS hostname resolves to reachable A/AAAA addresses."
        };
    }
}


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

        map[MtaStsCodes.MissingRecord] = new RecommendationAdvice {
            Code = MtaStsCodes.MissingRecord,
            Title = "Publish an MTA-STS policy",
            Why = "Without MTA-STS, SMTP TLS remains opportunistic and subject to downgrade.",
            How = "Publish a DNS TXT at _mta-sts.<domain> and host https://mta-sts.<domain>/.well-known/mta-sts.txt with valid mode/max_age/mx.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc8461" },
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "mta-sts", "tls" }
        };
        map[MtaStsCodes.PolicyInvalid] = new RecommendationAdvice {
            Code = MtaStsCodes.PolicyInvalid,
            Title = "Fix invalid MTA-STS policy",
            Why = "Invalid policies are ignored by receivers, leaving mail vulnerable to downgrade.",
            How = "Ensure required fields (version: STSv1, mode, max_age, mx) are present and syntactically correct.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc8461" },
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "mta-sts" }
        };
        map[MtaStsCodes.NotEnforcing] = new RecommendationAdvice {
            Code = MtaStsCodes.NotEnforcing,
            Title = "Enable MTA-STS enforcement when ready",
            Why = "'testing' mode does not enforce TLS; use 'enforce' after validation to block downgrade attacks.",
            How = "Change policy 'mode' to 'enforce' once configuration is verified and monitoring is in place.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc8461" },
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "mta-sts" }
        };
        map[MtaStsCodes.Enforced] = new RecommendationAdvice {
            Code = MtaStsCodes.Enforced,
            Title = "MTA-STS enforced",
            Why = "Enforced policies protect mail against TLS downgrade.",
            How = "Monitor reports and keep policy current.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc8461" },
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "mta-sts" }
        };

        map[MtaStsCodes.PolicyValid] = new RecommendationAdvice {
            Code = MtaStsCodes.PolicyValid,
            Title = "MTA-STS policy valid",
            Why = "A syntactically correct policy enables secure SMTP TLS enforcement.",
            How = "Keep policy fields (version, mode, max_age, mx) correct and up to date.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc8461" },
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "mta-sts", "tls" },
            Impact = "Helps prevent mail downgrade attacks.",
            Effort = RecommendationEffort.Low,
            Verify = "Fetch policy and ensure required fields are present."
        };

        map[MtaStsCodes.HttpsAvailable] = new RecommendationAdvice {
            Code = MtaStsCodes.HttpsAvailable,
            Title = "MTA-STS policy HTTPS reachable",
            Why = "Senders must retrieve the policy over HTTPS to trust it.",
            How = "Serve the policy at https://mta-sts.<domain>/.well-known/mta-sts.txt with a valid certificate.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc8461" },
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "mta-sts", "https" },
            Impact = "Enables secure policy distribution.",
            Effort = RecommendationEffort.Low,
            Verify = "GET https://mta-sts.<domain>/.well-known/mta-sts.txt returns 200."
        };

        map[MtaStsCodes.MxStartTlsMissing] = new RecommendationAdvice {
            Code = MtaStsCodes.MxStartTlsMissing,
            Title = "Some MX hosts do not advertise STARTTLS",
            Why = "MTA-STS relies on STARTTLS support; hosts without STARTTLS will prevent secure delivery.",
            How = "Enable STARTTLS on all MX servers and ensure EHLO advertises STARTTLS.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc3207", "https://www.rfc-editor.org/rfc/rfc8461" },
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "starttls", "mta-sts" },
            Impact = "Mail may fall back to plaintext or be deferred under enforcement.",
            Effort = RecommendationEffort.Medium,
            Verify = "EHLO lists STARTTLS on each MX; STARTTLS negotiation succeeds."
        };

        map[MtaStsCodes.MxTlsWeak] = new RecommendationAdvice {
            Code = MtaStsCodes.MxTlsWeak,
            Title = "Weak TLS negotiated on some MX hosts",
            Why = "Legacy TLS or weak cipher suites reduce confidentiality and integrity of SMTP sessions.",
            How = "Disable TLS 1.0/1.1, prefer TLS 1.2+ and modern ciphers; update libraries as needed.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc8996" },
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "tls", "cipher" },
            Impact = "Susceptible to downgrade or cryptographic attacks.",
            Effort = RecommendationEffort.Medium,
            Verify = "All MX negotiate TLS 1.2+ with forward secrecy; no legacy protocols offered."
        };

        map[MtaStsCodes.MxTlsModernAll] = new RecommendationAdvice {
            Code = MtaStsCodes.MxTlsModernAll,
            Title = "All MX hosts negotiate modern TLS",
            Why = "Modern TLS versions and ciphers ensure strong transport security end-to-end.",
            How = "Maintain TLS 1.2/1.3 and modern cipher suites; renew certificates in time.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc8996" },
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "tls" },
            Impact = "Improves confidentiality and prevents downgrade.",
            Effort = RecommendationEffort.Low,
            Verify = "Each MX grades at B or better; TLS 1.2+ negotiated."
        };

        map[MtaStsCodes.ProviderRecommended] = new RecommendationAdvice {
            Code = MtaStsCodes.ProviderRecommended,
            Title = "Enable MTA-STS for detected provider",
            Why = "Gateway/primary providers benefit from MTA-STS to prevent TLS downgrade and improve delivery reliability.",
            How = "Publish _mta-sts TXT and host an 'enforce' policy when ready. Keep MX patterns aligned.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc8461" },
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "mta-sts", "provider" }
        };
    }
}

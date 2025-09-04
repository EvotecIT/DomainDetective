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
    }
}

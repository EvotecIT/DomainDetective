using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class SmtpAuthRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[SmtpAuthCodes.AuthWithout8BitMime] = new RecommendationAdvice {
            Code = SmtpAuthCodes.AuthWithout8BitMime,
            Title = "AUTH advertised without 8BITMIME",
            Why = "Some clients expect 8BITMIME when AUTH is present; missing it can cause encoding issues.",
            How = "Enable the 8BITMIME extension alongside AUTH in EHLO capabilities.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc6152" },
            Domain = RecommendationDomain.EmailAuth,
            Tags = new [] { "smtp", "auth" },
            Impact = "Intermittent client failures with non-ASCII content.",
            Effort = RecommendationEffort.Low,
            Verify = "Check EHLO response lists 8BITMIME and AUTH."
        };

        map[SmtpAuthCodes.CheckFailed] = new RecommendationAdvice {
            Code = SmtpAuthCodes.CheckFailed,
            Title = "SMTP AUTH check failed",
            Why = "Authentication capability is misconfigured or failing; clients may fall back to insecure methods.",
            How = "Verify SASL mechanisms, TLS protection, and server logs for AUTH negotiation errors.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc4954" },
            Domain = RecommendationDomain.EmailAuth,
            Tags = new [] { "smtp", "auth" }
        };

        map[SmtpAuthCodes.AuthOverPlaintext] = new RecommendationAdvice {
            Code = SmtpAuthCodes.AuthOverPlaintext,
            Title = "AUTH advertised without STARTTLS",
            Why = "Advertising AUTH without STARTTLS on 25/587 enables credential interception.",
            How = "Enable STARTTLS and require TLS before AUTH; or disable AUTH on plaintext listeners.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc4954" },
            Domain = RecommendationDomain.EmailAuth,
            Tags = new [] { "smtp", "starttls" },
            Impact = "High risk of credential theft.",
            Effort = RecommendationEffort.Low,
            Verify = "EHLO should list STARTTLS and server should require TLS prior to AUTH."
        };

        map[SmtpAuthCodes.ObsoleteMechanism] = new RecommendationAdvice {
            Code = SmtpAuthCodes.ObsoleteMechanism,
            Title = "Obsolete SMTP AUTH mechanism enabled",
            Why = "Legacy mechanisms like NTLM or CRAM-MD5 are weaker and may be deprecated.",
            How = "Disable NTLM/CRAM-MD5; prefer OAuthBearER or SCRAM family over TLS.",
            Links = new [] { "https://datatracker.ietf.org/doc/html/rfc8314" },
            Domain = RecommendationDomain.EmailAuth,
            Tags = new [] { "smtp", "sasl" },
            Impact = "Reduced authentication strength.",
            Effort = RecommendationEffort.Low,
            Verify = "EHLO AUTH line should not include NTLM or CRAM-MD5."
        };

        map[SmtpAuthCodes.NoStrongMechanism] = new RecommendationAdvice {
            Code = SmtpAuthCodes.NoStrongMechanism,
            Title = "Only weak AUTH mechanisms available",
            Why = "Providing only PLAIN/LOGIN limits defense-in-depth even with TLS.",
            How = "Enable stronger mechanisms like SCRAM-SHA-256 or OAuth-based SASL where supported.",
            Links = new [] { "https://datatracker.ietf.org/doc/html/rfc5802" },
            Domain = RecommendationDomain.EmailAuth,
            Tags = new [] { "smtp", "sasl" },
            Impact = "Weaker resistance to credential disclosure.",
            Effort = RecommendationEffort.Medium,
            Verify = "EHLO AUTH should include a strong mechanism alongside PLAIN/LOGIN."
        };
    }
}

using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class SmtpBannerRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[SmtpBannerCodes.MissingDomain] = new RecommendationAdvice {
            Code = SmtpBannerCodes.MissingDomain,
            Title = "SMTP banner missing domain name",
            Why = "RFC 5321 recommends including the server's domain in the 220 greeting.",
            How = "Configure the MTA to include a valid hostname in the banner (e.g., '220 mail.example.com ESMTP').",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc5321" },
            Domain = RecommendationDomain.EmailAuth,
            Tags = new [] { "smtp", "banner" },
            Effort = RecommendationEffort.Low,
            Verify = "Reconnect and ensure the greeting includes the correct hostname.",
        };

        map[SmtpBannerCodes.Not220] = new RecommendationAdvice {
            Code = SmtpBannerCodes.Not220,
            Title = "SMTP greeting not 220",
            Why = "The initial response should be a 220 greeting; other codes indicate misconfiguration.",
            How = "Adjust the server configuration or middleware to present a proper 220 greeting.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc5321" },
            Domain = RecommendationDomain.EmailAuth,
            Tags = new [] { "smtp", "banner" },
            Effort = RecommendationEffort.Low,
            Verify = "Reconnect and confirm a 220 greeting is sent.",
        };

        map[SmtpBannerCodes.VersionLeaked] = new RecommendationAdvice {
            Code = SmtpBannerCodes.VersionLeaked,
            Title = "SMTP banner exposes software version",
            Why = "Version disclosure eases targeted exploitation using known CVEs.",
            How = "Configure the MTA to suppress or generalize version strings in the banner.",
            Links = new [] { "https://owasp.org/www-project-web-security-testing-guide/" },
            Domain = RecommendationDomain.EmailAuth,
            Tags = new [] { "banner", "information-disclosure" },
            Effort = RecommendationEffort.Low,
            Verify = "Reconnect and verify version tokens are no longer present.",
        };

        map[SmtpBannerCodes.UnexpectedSoftware] = new RecommendationAdvice {
            Code = SmtpBannerCodes.UnexpectedSoftware,
            Title = "SMTP software differs from expectation",
            Why = "Mismatch may indicate incorrect host, proxy, or unapproved software.",
            How = "Validate deployment; align ExpectedSoftware configuration with the actual MTA or update the host.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc5321" },
            Domain = RecommendationDomain.EmailAuth,
            Tags = new [] { "smtp", "banner" },
            Effort = RecommendationEffort.Medium,
            Verify = "Confirm banner matches the authorized MTA software.",
        };

        map[SmtpBannerCodes.HostnameMatch] = new RecommendationAdvice {
            Code = SmtpBannerCodes.HostnameMatch,
            Title = "SMTP banner includes expected hostname",
            Why = "Correct hostnames improve deliverability and simplify troubleshooting.",
            How = "No action required; ensure deployments keep the banner aligned with the host.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc5321" },
            Domain = RecommendationDomain.EmailAuth,
            Tags = new [] { "smtp", "banner" },
            Effort = RecommendationEffort.Low,
            Verify = "Reconnect and confirm the hostname remains accurate.",
        };

        map[SmtpBannerCodes.TlsAdvertised] = new RecommendationAdvice {
            Code = SmtpBannerCodes.TlsAdvertised,
            Title = "SMTP banner advertises TLS",
            Why = "Advertising TLS encourages clients to establish encrypted sessions.",
            How = "No action required; maintain TLS support and advertisement.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc3207" },
            Domain = RecommendationDomain.EmailAuth,
            Tags = new [] { "smtp", "tls" },
            Effort = RecommendationEffort.Low,
            Verify = "Reconnect and verify TLS is still advertised.",
        };
    }
}


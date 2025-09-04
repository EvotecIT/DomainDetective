using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class SecurityTxtRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[SecurityTxtCodes.RecordPresent] = new RecommendationAdvice {
            Code = SecurityTxtCodes.RecordPresent,
            Title = "security.txt present",
            Why = "A published security.txt gives researchers a defined channel to report issues.",
            How = "Serve /.well-known/security.txt over HTTPS with contact and policy details.",
            Links = new [] { "https://securitytxt.org/" },
            Domain = RecommendationDomain.Privacy,
            Tags = new [] { "security.txt" },
            Impact = "Facilitates responsible disclosure.",
            Effort = RecommendationEffort.Low,
            Verify = "GET https://<domain>/.well-known/security.txt returns policy file."
        };

        map[SecurityTxtCodes.RecordValid] = new RecommendationAdvice {
            Code = SecurityTxtCodes.RecordValid,
            Title = "security.txt syntax valid",
            Why = "Valid syntax ensures automated tools can parse the disclosure policy.",
            How = "Include required fields and follow formatting guidance.",
            Links = new [] { "https://securitytxt.org/" },
            Domain = RecommendationDomain.Privacy,
            Tags = new [] { "security.txt" },
            Impact = "Improves trust and interoperability.",
            Effort = RecommendationEffort.Low,
            Verify = "Run a security.txt parser without errors."
        };

        map[SecurityTxtCodes.MissingContact] = new RecommendationAdvice {
            Code = SecurityTxtCodes.MissingContact,
            Title = "security.txt: missing Contact",
            Why = "Without a contact, researchers cannot report vulnerabilities responsibly.",
            How = "Add a Contact: mailto:security@<domain> (or a web form).",
            Links = new [] { "https://securitytxt.org/" },
            Domain = RecommendationDomain.Privacy,
            Tags = new [] { "security.txt" },
            Impact = "Slower vulnerability disclosure; increased exposure time.",
            Effort = RecommendationEffort.Low,
            Verify = "Fetch /.well-known/security.txt and confirm Contact exists."
        };

        map[SecurityTxtCodes.CanonicalNotHttps] = new RecommendationAdvice {
            Code = SecurityTxtCodes.CanonicalNotHttps,
            Title = "security.txt Canonical must use HTTPS",
            Why = "HTTP canonical URLs are not trusted.",
            How = "Use an https:// URL for the Canonical field.",
            Links = new [] { "https://securitytxt.org/" },
            Domain = RecommendationDomain.Privacy,
            Tags = new [] { "security.txt" },
            Impact = "Lower trust in published disclosure policy.",
            Effort = RecommendationEffort.Low,
            Verify = "Inspect Canonical value is https://."
        };

        map[SecurityTxtCodes.SignatureVerifyFailed] = new RecommendationAdvice {
            Code = SecurityTxtCodes.SignatureVerifyFailed,
            Title = "security.txt PGP signature failed",
            Why = "Unverifiable signatures reduce trust in the policy file.",
            How = "Ensure the PGP key is accessible and the signature matches the policy content.",
            Links = new [] { "https://securitytxt.org/" },
            Domain = RecommendationDomain.Privacy,
            Tags = new [] { "security.txt", "pgp" },
            Impact = "Consumers cannot validate authenticity of the policy.",
            Effort = RecommendationEffort.Medium,
            Verify = "Verify clear-signed file using the published PGP key."
        };
    }
}

using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class HttpRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[HttpCodes.HpkpDeprecated] = new RecommendationAdvice {
            Code = HttpCodes.HpkpDeprecated,
            Title = "HPKP header is obsolete",
            Why = "HTTP Public Key Pinning (HPKP) has been removed from browsers and can brick sites when misconfigured.",
            How = "Remove the Public-Key-Pins header. Prefer Certificate Transparency monitoring and short-lived certificates.",
            Links = new [] { "https://developer.chrome.com/blog/chrome-security-headers/#public-key-pinning-hpkp", "https://datatracker.ietf.org/doc/html/rfc7469" },
            Domain = RecommendationDomain.Http,
            Tags = new [] { "headers", "deprecated" },
            Impact = "Can brick sites and is not honored by modern browsers.",
            Effort = RecommendationEffort.Low,
            Verify = "Confirm 'Public-Key-Pins' header is no longer present."
        };

        map[HttpCodes.HstsMissing] = new RecommendationAdvice {
            Code = HttpCodes.HstsMissing,
            Title = "Enable HSTS",
            Why = "Without HSTS, browsers may downgrade to HTTP and expose users to SSL stripping attacks.",
            How = "Add Strict-Transport-Security with 'max-age=31536000; includeSubDomains; preload' when ready. Verify all subdomains support HTTPS first.",
            Links = new [] { "https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security", "https://hstspreload.org/" },
            Domain = RecommendationDomain.Http,
            Tags = new [] { "headers", "hsts" },
            Impact = "Enables downgrade protection and protects cookies on first party.",
            Effort = RecommendationEffort.Low,
            Verify = "Fetch a page and check S-T-S header with expected directives."
        };

        map[HttpCodes.HstsTooShort] = new RecommendationAdvice {
            Code = HttpCodes.HstsTooShort,
            Title = "Increase HSTS max-age",
            Why = "Short HSTS policies do not meaningfully protect against downgrade or cookie theft.",
            How = "Raise max-age to at least 10886400 (18 weeks); for preload eligibility use 31536000 (1 year).",
            Links = new [] { "https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security" },
            Domain = RecommendationDomain.Http,
            Tags = new [] { "headers", "hsts" },
            Impact = "Weakens downgrade protection window.",
            Effort = RecommendationEffort.Low,
            Verify = "Inspect S-T-S header max-age meets threshold."
        };

        map[HttpCodes.CspUnsafe] = new RecommendationAdvice {
            Code = HttpCodes.CspUnsafe,
            Title = "CSP allows unsafe directives",
            Why = "'unsafe-inline' or 'unsafe-eval' weaken CSP and allow XSS execution paths.",
            How = "Remove 'unsafe-inline'/'unsafe-eval'. Use nonces or hashes for inline scripts and adopt strict CSP patterns.",
            Links = new [] { "https://developer.mozilla.org/docs/Web/HTTP/CSP", "https://csp-evaluator.withgoogle.com/" },
            Domain = RecommendationDomain.Http,
            Tags = new [] { "headers", "csp" },
            Impact = "Increased risk of cross-site scripting.",
            Effort = RecommendationEffort.Medium,
            Verify = "Evaluate with CSP Evaluator; ensure no unsafe directives remain."
        };

        map[HttpCodes.MixedContent] = new RecommendationAdvice {
            Code = HttpCodes.MixedContent,
            Title = "Mixed content on HTTPS page",
            Why = "Loading http:// resources on an HTTPS page breaks integrity and can leak or alter content.",
            How = "Serve all subresources over HTTPS. Replace hard-coded http:// URLs with protocol-relative or https:// equivalents.",
            Links = new [] { "https://developer.mozilla.org/docs/Web/Security/Mixed_content" },
            Domain = RecommendationDomain.Http,
            Tags = new [] { "mixed-content" },
            Impact = "Compromised confidentiality/integrity for active or passive content.",
            Effort = RecommendationEffort.Medium,
            Verify = "Run a crawl or browser devtools audit; ensure no http:// subresources."
        };

        map[HttpCodes.MissingHeaderCsp] = new RecommendationAdvice {
            Code = HttpCodes.MissingHeaderCsp,
            Title = "Set a Content-Security-Policy",
            Why = "CSP reduces XSS risk by restricting sources of executable content.",
            How = "Start with a report-only CSP, audit violations, then enforce. Prefer nonces/hashes and limit script origins.",
            Links = new [] { "https://developer.mozilla.org/docs/Web/HTTP/CSP", "https://csp.withgoogle.com/docs/index.html" },
            Domain = RecommendationDomain.Http,
            Tags = new [] { "headers", "csp" },
            Impact = "No protection layer against unintended script execution.",
            Effort = RecommendationEffort.Medium,
            Verify = "Confirm CSP header present and reports (in report-only) show no critical violations."
        };

        map[HttpCodes.MissingHeaderReferrerPolicy] = new RecommendationAdvice {
            Code = HttpCodes.MissingHeaderReferrerPolicy,
            Title = "Set a Referrer-Policy",
            Why = "Without a policy, browsers may leak full URLs (including query strings) across origins.",
            How = "Add 'Referrer-Policy: no-referrer-when-downgrade' or stricter like 'strict-origin-when-cross-origin'.",
            Links = new [] { "https://developer.mozilla.org/docs/Web/HTTP/Headers/Referrer-Policy" },
            Domain = RecommendationDomain.Http,
            Tags = new [] { "headers" },
            Impact = "Potential leakage of sensitive query data to third parties.",
            Effort = RecommendationEffort.Low,
            Verify = "Confirm 'Referrer-Policy' header appears with desired value."
        };

        map[HttpCodes.MissingHeaderXContentTypeOptions] = new RecommendationAdvice {
            Code = HttpCodes.MissingHeaderXContentTypeOptions,
            Title = "Send X-Content-Type-Options: nosniff",
            Why = "Prevents MIME-type sniffing that can lead to script execution in some browsers.",
            How = "Add 'X-Content-Type-Options: nosniff' on all responses.",
            Links = new [] { "https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Content-Type-Options" },
            Domain = RecommendationDomain.Http,
            Tags = new [] { "headers" },
            Impact = "Certain browsers may treat non-script responses as script.",
            Effort = RecommendationEffort.Low,
            Verify = "Confirm header present on representative endpoints."
        };
    }
}

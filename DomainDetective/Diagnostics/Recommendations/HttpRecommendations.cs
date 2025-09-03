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
            How = "Add Strict-Transport-Security with 'max-age=31536000; includeSubDomains; preload' when ready. Verify all subdomains support HTTPS first.\n\nExamples:\n- nginx: add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\n- Apache: Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"\n- Cloudflare: Rules -> Transform -> Response Header -> Set S-T-S",
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

        map[HttpCodes.InsecureFormAction] = new RecommendationAdvice {
            Code = HttpCodes.InsecureFormAction,
            Title = "Form submits over insecure HTTP",
            Why = "Posting sensitive data from an HTTPS page to an http:// endpoint exposes credentials and form contents.",
            How = "Update form action URLs to https:// and ensure the destination endpoint supports TLS. Avoid absolute http:// links.",
            Links = new [] { "https://developer.mozilla.org/docs/Web/Security/Mixed_content#forms_and_iframes" },
            Domain = RecommendationDomain.Http,
            Tags = new [] { "forms", "mixed-content" },
            Impact = "Credentials or PII can be intercepted or modified in transit.",
            Effort = RecommendationEffort.Low,
            Verify = "Inspect <form> action attributes; confirm all are https:// or relative (which inherit https)."
        };

        map[HttpCodes.MissingHeaderCsp] = new RecommendationAdvice {
            Code = HttpCodes.MissingHeaderCsp,
            Title = "Set a Content-Security-Policy",
            Why = "CSP reduces XSS risk by restricting sources of executable content.",
            How = "Start with a report-only CSP, audit violations, then enforce. Prefer nonces/hashes and limit script origins.\n\nExamples:\n- nginx: add_header Content-Security-Policy \"default-src 'self'; script-src 'self' 'nonce-<nonce>'; object-src 'none'\" always;\n- Apache: Header set Content-Security-Policy \"default-src 'self'\"\n- Cloudflare: Rules -> Transform -> Response Header -> Set CSP",
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
            How = "Add 'Referrer-Policy: no-referrer-when-downgrade' or stricter like 'strict-origin-when-cross-origin'.\n\nExamples:\n- nginx: add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n- Apache: Header set Referrer-Policy \"strict-origin-when-cross-origin\"",
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
            How = "Add 'X-Content-Type-Options: nosniff' on all responses.\n\nExamples:\n- nginx: add_header X-Content-Type-Options \"nosniff\" always;\n- Apache: Header set X-Content-Type-Options \"nosniff\"",
            Links = new [] { "https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Content-Type-Options" },
            Domain = RecommendationDomain.Http,
            Tags = new [] { "headers" },
            Impact = "Certain browsers may treat non-script responses as script.",
            Effort = RecommendationEffort.Low,
            Verify = "Confirm header present on representative endpoints."
        };

        map[HttpCodes.XFrameOptionsInvalid] = new RecommendationAdvice {
            Code = HttpCodes.XFrameOptionsInvalid,
            Title = "Use a valid X-Frame-Options value",
            Why = "Invalid or obsolete X-Frame-Options values may not be honored, leaving pages vulnerable to clickjacking.",
            How = "Set 'X-Frame-Options' to 'DENY' (preferable) or 'SAMEORIGIN'. 'ALLOW-FROM' is obsolete and should be avoided.\n\nExamples:\n- nginx: add_header X-Frame-Options \"DENY\" always;\n- Apache: Header set X-Frame-Options \"SAMEORIGIN\"",
            Links = new [] { "https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Frame-Options" },
            Domain = RecommendationDomain.Http,
            Tags = new [] { "headers", "clickjacking" },
            Impact = "Frames can overlay UI and trick users into unintended actions.",
            Effort = RecommendationEffort.Low,
            Verify = "Confirm header equals 'DENY' or 'SAMEORIGIN' on responses."
        };

        map[HttpCodes.XContentTypeOptionsInvalid] = new RecommendationAdvice {
            Code = HttpCodes.XContentTypeOptionsInvalid,
            Title = "Correct X-Content-Type-Options value",
            Why = "Only 'nosniff' is valid. Other values are ignored, reducing protection against content sniffing.",
            How = "Set 'X-Content-Type-Options: nosniff' exactly.\n\nExamples:\n- nginx: add_header X-Content-Type-Options \"nosniff\" always;\n- Apache: Header set X-Content-Type-Options \"nosniff\"",
            Links = new [] { "https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Content-Type-Options" },
            Domain = RecommendationDomain.Http,
            Tags = new [] { "headers" },
            Impact = "Browsers may attempt to sniff content types increasing XSS risk.",
            Effort = RecommendationEffort.Low,
            Verify = "Confirm header equals 'nosniff' on responses."
        };
        map[HttpCodes.CspReportOnly] = new RecommendationAdvice {
            Code = HttpCodes.CspReportOnly,
            Title = "CSP is report-only",
            Why = "Report-only CSP does not block violations and leaves risk window open.",
            How = "Audit reports, fix issues, then move to enforcement by sending Content-Security-Policy (not report-only).",
            Links = new [] { "https://developer.mozilla.org/docs/Web/HTTP/CSP" },
            Domain = RecommendationDomain.Http,
            Tags = new [] { "headers", "csp" },
            Impact = "Violations are not prevented; only logged.",
            Effort = RecommendationEffort.Medium,
            Verify = "Confirm Content-Security-Policy header is present and report-only removed."
        };

        map[HttpCodes.PermissionsPolicyWeak] = new RecommendationAdvice {
            Code = HttpCodes.PermissionsPolicyWeak,
            Title = "Tighten Permissions-Policy values",
            Why = "Empty or wildcard feature policies do not restrict powerful APIs and defeat the purpose of the header.",
            How = "Set explicit allow-lists per feature (e.g., camera=(), geolocation=()). Avoid '*' or empty lists.",
            Links = new [] { "https://developer.mozilla.org/docs/Web/HTTP/Headers/Permissions-Policy" },
            Domain = RecommendationDomain.Http,
            Tags = new [] { "headers" },
            Impact = "Broader exposure to API abuse in embedded contexts.",
            Effort = RecommendationEffort.Low,
            Verify = "Inspect header to ensure each feature has a principled allow-list."
        };

        map[HttpCodes.MissingHeaderPermissionsPolicy] = new RecommendationAdvice {
            Code = HttpCodes.MissingHeaderPermissionsPolicy,
            Title = "Set Permissions-Policy",
            Why = "Controls access to powerful features (camera, geolocation, etc.) by origin and embedding context.",
            How = "Add 'Permissions-Policy' with explicit allow-lists, e.g., 'camera=(), geolocation=()'.",
            Links = new [] { "https://developer.mozilla.org/docs/Web/HTTP/Headers/Permissions-Policy" },
            Domain = RecommendationDomain.Http,
            Tags = new [] { "headers" },
            Impact = "Features may be accessible by default in iframes or third-party contexts.",
            Effort = RecommendationEffort.Low,
            Verify = "Confirm header present with intended feature lists."
        };

        map[HttpCodes.MissingHeaderCOOP] = new RecommendationAdvice {
            Code = HttpCodes.MissingHeaderCOOP,
            Title = "Set Cross-Origin-Opener-Policy",
            Why = "COOP isolates browsing contexts to mitigate cross-origin attacks and Spectre-like leaks.",
            How = "Add 'Cross-Origin-Opener-Policy: same-origin' on top-level documents where isolation is acceptable.",
            Links = new [] { "https://developer.mozilla.org/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy" },
            Domain = RecommendationDomain.Http,
            Tags = new [] { "headers", "isolation" },
            Impact = "Shared browsing context with cross-origin pages; data leakage risk.",
            Effort = RecommendationEffort.Low,
            Verify = "Confirm header present and equals 'same-origin'."
        };

        map[HttpCodes.MissingHeaderCOEP] = new RecommendationAdvice {
            Code = HttpCodes.MissingHeaderCOEP,
            Title = "Set Cross-Origin-Embedder-Policy",
            Why = "COEP enforces that embedded resources are CORS-enabled or CORP-protected, enabling strong isolation.",
            How = "Add 'Cross-Origin-Embedder-Policy: require-corp' when all subresources are compliant.",
            Links = new [] { "https://developer.mozilla.org/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy" },
            Domain = RecommendationDomain.Http,
            Tags = new [] { "headers", "isolation" },
            Impact = "Without COEP, strong process isolation (with COOP) is not achieved.",
            Effort = RecommendationEffort.Medium,
            Verify = "Confirm header present and equals 'require-corp'."
        };

        map[HttpCodes.MissingHeaderCORP] = new RecommendationAdvice {
            Code = HttpCodes.MissingHeaderCORP,
            Title = "Set Cross-Origin-Resource-Policy",
            Why = "CORP restricts which origins can load your resources, protecting against cross-origin data leaks.",
            How = "Add 'Cross-Origin-Resource-Policy: same-origin' (or 'same-site' if needed for subdomains).",
            Links = new [] { "https://developer.mozilla.org/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy" },
            Domain = RecommendationDomain.Http,
            Tags = new [] { "headers", "isolation" },
            Impact = "Resources can be embedded cross-origin without explicit consent.",
            Effort = RecommendationEffort.Low,
            Verify = "Confirm header present with a restrictive value."
        };

        map[HttpCodes.COOPWeak] = new RecommendationAdvice {
            Code = HttpCodes.COOPWeak,
            Title = "Harden COOP",
            Why = "'unsafe-none' does not isolate browsing contexts.",
            How = "Use 'Cross-Origin-Opener-Policy: same-origin' on top-level documents.",
            Links = new [] { "https://developer.mozilla.org/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy" },
            Domain = RecommendationDomain.Http,
            Tags = new [] { "headers", "isolation" },
            Impact = "Cross-origin popups/iframed contexts can share browsing context.",
            Effort = RecommendationEffort.Low,
            Verify = "Confirm COOP equals 'same-origin'."
        };

        map[HttpCodes.COEPWeak] = new RecommendationAdvice {
            Code = HttpCodes.COEPWeak,
            Title = "Harden COEP",
            Why = "COEP must be 'require-corp' for strong isolation.",
            How = "Set 'Cross-Origin-Embedder-Policy: require-corp' and ensure subresources use CORS or CORP.",
            Links = new [] { "https://developer.mozilla.org/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy" },
            Domain = RecommendationDomain.Http,
            Tags = new [] { "headers", "isolation" },
            Impact = "Subresources may be loaded without CORS/CORP constraints.",
            Effort = RecommendationEffort.Medium,
            Verify = "Confirm COEP equals 'require-corp'."
        };

        // Presence/positive signals
        map[HttpCodes.HstsPresent] = new RecommendationAdvice {
            Code = HttpCodes.HstsPresent,
            Title = "HSTS present",
            Why = "HSTS enforces HTTPS and mitigates downgrade/strip attacks.",
            How = "Maintain Strict-Transport-Security with adequate max-age; consider preload eligibility.",
            Domain = RecommendationDomain.Http,
            Tags = new [] { "hsts" },
            Impact = "Stronger transport security posture.",
            Effort = RecommendationEffort.Low,
            Verify = "Confirm S-T-S header with max-age and includeSubDomains as intended."
        };
        map[HttpCodes.CspPresent] = new RecommendationAdvice {
            Code = HttpCodes.CspPresent,
            Title = "CSP present",
            Why = "A well-configured CSP reduces XSS risk and tightens resource loading.",
            How = "Maintain CSP with nonces/hashes; avoid report-only and unsafe directives.",
            Domain = RecommendationDomain.Http,
            Tags = new [] { "csp" },
            Impact = "Improved client-side hardening.",
            Effort = RecommendationEffort.Medium,
            Verify = "Inspect CSP header; ensure enforcement (not report-only)."
        };
        map[HttpCodes.ReferrerPolicyPresent] = new RecommendationAdvice {
            Code = HttpCodes.ReferrerPolicyPresent,
            Title = "Referrer-Policy present",
            Why = "Controlling referrer reduces leakage of sensitive URLs across origins.",
            How = "Set a strict policy (e.g., no-referrer, strict-origin-when-cross-origin) according to your needs.",
            Domain = RecommendationDomain.Http,
            Tags = new [] { "referrer" },
            Effort = RecommendationEffort.Low,
            Verify = "Header present with intended value."
        };
        map[HttpCodes.XFrameOptionsPresent] = new RecommendationAdvice {
            Code = HttpCodes.XFrameOptionsPresent,
            Title = "X-Frame-Options present",
            Why = "Prevents clickjacking by disallowing framing.",
            How = "Keep DENY or SAMEORIGIN as applicable.",
            Domain = RecommendationDomain.Http,
            Tags = new [] { "xfo" },
            Effort = RecommendationEffort.Low,
            Verify = "Header equals DENY or SAMEORIGIN."
        };
        map[HttpCodes.XContentTypeOptionsPresent] = new RecommendationAdvice {
            Code = HttpCodes.XContentTypeOptionsPresent,
            Title = "X-Content-Type-Options nosniff present",
            Why = "Disables MIME sniffing to prevent content-type confusion.",
            How = "Keep 'nosniff' on all responses serving untrusted content.",
            Domain = RecommendationDomain.Http,
            Tags = new [] { "xcto" },
            Effort = RecommendationEffort.Low,
            Verify = "Header equals 'nosniff'."
        };
        map[HttpCodes.PermissionsPolicyPresent] = new RecommendationAdvice {
            Code = HttpCodes.PermissionsPolicyPresent,
            Title = "Permissions-Policy present",
            Why = "Restricts access to powerful features by origin/context.",
            How = "Maintain explicit allow-lists per feature; avoid '*' or empty lists.",
            Domain = RecommendationDomain.Http,
            Tags = new [] { "permissions-policy" },
            Effort = RecommendationEffort.Low,
            Verify = "Header present with non-wildcard feature values."
        };
        map[HttpCodes.COOPPresent] = new RecommendationAdvice {
            Code = HttpCodes.COOPPresent,
            Title = "COOP present",
            Why = "Enables process isolation for top-level documents.",
            How = "Maintain 'same-origin' where isolation is desired.",
            Domain = RecommendationDomain.Http,
            Tags = new [] { "coop" },
            Effort = RecommendationEffort.Low,
            Verify = "Header equals 'same-origin'."
        };
        map[HttpCodes.COEPPresent] = new RecommendationAdvice {
            Code = HttpCodes.COEPPresent,
            Title = "COEP present",
            Why = "Enforces CORS/CORP compliance for embedded resources, enabling isolation.",
            How = "Maintain 'require-corp' once all subresources are compliant.",
            Domain = RecommendationDomain.Http,
            Tags = new [] { "coep" },
            Effort = RecommendationEffort.Medium,
            Verify = "Header equals 'require-corp'."
        };
        map[HttpCodes.CORPPresent] = new RecommendationAdvice {
            Code = HttpCodes.CORPPresent,
            Title = "CORP present",
            Why = "Restricts which origins can load your resources.",
            How = "Prefer 'same-origin' (or 'same-site' if needed).",
            Domain = RecommendationDomain.Http,
            Tags = new [] { "corp" },
            Effort = RecommendationEffort.Low,
            Verify = "Header equals 'same-origin' or 'same-site'."
        };
        map[HttpCodes.OACEnabled] = new RecommendationAdvice {
            Code = HttpCodes.OACEnabled,
            Title = "Origin-Agent-Cluster enabled",
            Why = "Improves site isolation and security by clustering same-origin contexts.",
            How = "Maintain 'Origin-Agent-Cluster: ?1' where supported.",
            Domain = RecommendationDomain.Http,
            Tags = new [] { "oac", "isolation" },
            Effort = RecommendationEffort.Low,
            Verify = "Header present and equals '?1'."
        };

        map[HttpCodes.CORPWeak] = new RecommendationAdvice {
            Code = HttpCodes.CORPWeak,
            Title = "Harden CORP",
            Why = "Less restrictive CORP values allow broader cross-origin embedding.",
            How = "Set 'Cross-Origin-Resource-Policy: same-origin' or at least 'same-site' where needed.",
            Links = new [] { "https://developer.mozilla.org/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy" },
            Domain = RecommendationDomain.Http,
            Tags = new [] { "headers", "isolation" },
            Impact = "Cross-origin sites may load your resources without consent.",
            Effort = RecommendationEffort.Low,
            Verify = "Confirm CORP equals 'same-origin' or 'same-site'."
        };

        map[HttpCodes.MissingHeaderOAC] = new RecommendationAdvice {
            Code = HttpCodes.MissingHeaderOAC,
            Title = "Set Origin-Agent-Cluster",
            Why = "OAC instructs browsers to isolate the origin into its own agent cluster.",
            How = "Add 'Origin-Agent-Cluster: ?1' on top-level documents where isolation is safe.",
            Links = new [] { "https://developer.mozilla.org/docs/Web/HTTP/Headers/Origin-Agent-Cluster" },
            Domain = RecommendationDomain.Http,
            Tags = new [] { "headers", "isolation" },
            Impact = "Less process isolation; potential Spectre-like risk.",
            Effort = RecommendationEffort.Low,
            Verify = "Confirm header present and equals '?1'."
        };

        map[HttpCodes.MissingHeaderXPermittedCrossDomainPolicies] = new RecommendationAdvice {
            Code = HttpCodes.MissingHeaderXPermittedCrossDomainPolicies,
            Title = "Set X-Permitted-Cross-Domain-Policies",
            Why = "Restricts Adobe Flash/Acrobat cross-domain data loading (legacy but still seen).",
            How = "Add 'X-Permitted-Cross-Domain-Policies: none' unless legacy integrations require otherwise.",
            Links = new [] { "https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Permitted-Cross-Domain-Policies" },
            Domain = RecommendationDomain.Http,
            Tags = new [] { "headers" },
            Impact = "Legacy clients may load data across origins without constraints.",
            Effort = RecommendationEffort.Low,
            Verify = "Confirm header present with 'none' unless justified."
        };

        map[HttpCodes.ExpectCtDeprecated] = new RecommendationAdvice {
            Code = HttpCodes.ExpectCtDeprecated,
            Title = "Remove Expect-CT",
            Why = "Expect-CT is deprecated in browsers; rely on Certificate Transparency and SCTs instead.",
            How = "Remove the Expect-CT header; ensure certificates include embedded SCTs or via TLS extension.",
            Links = new [] { "https://developer.chrome.com/blog/chrome-security-headers/#expect-ct" },
            Domain = RecommendationDomain.Http,
            Tags = new [] { "headers", "deprecated" },
            Impact = "No impact on modern browsers; reduces header surface.",
            Effort = RecommendationEffort.Low,
            Verify = "Confirm header absent on responses."
        };

        map[HttpCodes.XssProtectionDeprecated] = new RecommendationAdvice {
            Code = HttpCodes.XssProtectionDeprecated,
            Title = "Remove X-XSS-Protection",
            Why = "X-XSS-Protection is obsolete; modern browsers disable or ignore it.",
            How = "Remove the header and enforce a strong CSP instead.",
            Links = new [] { "https://developer.mozilla.org/docs/Web/HTTP/Headers/X-XSS-Protection" },
            Domain = RecommendationDomain.Http,
            Tags = new [] { "headers", "deprecated" },
            Impact = "Reduces header bloat and avoids false sense of security.",
            Effort = RecommendationEffort.Low,
            Verify = "Confirm header absent and CSP enforced."
        };
    }
}

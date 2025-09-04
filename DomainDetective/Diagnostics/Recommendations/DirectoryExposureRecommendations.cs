using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class DirectoryExposureRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[DirectoryExposureCodes.ExposedDirectory] = new RecommendationAdvice {
            Code = DirectoryExposureCodes.ExposedDirectory,
            Title = "Directory listing exposed",
            Why = "Open indexes may disclose sensitive files or application structure.",
            How = "Disable directory listing or restrict access; add index files or configure server to return 403 for directories.",
            Links = new [] { "https://owasp.org/www-project-top-ten/" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "http", "hardening" },
            Impact = "Information disclosure may aid targeted attacks.",
            Effort = RecommendationEffort.Low,
            Verify = "Request common directories and confirm 403/404 or harmless index."
        };

        map[DirectoryExposureCodes.SecretsDotEnv] = new RecommendationAdvice {
            Code = DirectoryExposureCodes.SecretsDotEnv,
            Title = ".env file exposed",
            Why = ".env often contains credentials, API keys, or secrets.",
            How = "Remove .env from web root; load via environment or secure configuration; block access (403).",
            Links = new [] {
                "https://12factor.net/config",
                "https://owasp.org/www-project-top-ten/"
            },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "secrets", "http", "hardening" },
            Impact = "Credential leakage can lead to full compromise.",
            Effort = RecommendationEffort.Medium,
            Verify = "Request /.env returns 403/404 and secrets rotated if necessary."
        };

        map[DirectoryExposureCodes.BackupsPresent] = new RecommendationAdvice {
            Code = DirectoryExposureCodes.BackupsPresent,
            Title = "Backup files or folders exposed",
            Why = "Backup artifacts (.bak, ~, backup/) may reveal source code or data.",
            How = "Remove backup files from web root; restrict access; ensure version control ignores them.",
            Links = new [] { "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "backup", "hardening" },
            Impact = "Source disclosure or data leakage risk.",
            Effort = RecommendationEffort.Low,
            Verify = "Known backup paths return 403/404 and artifacts are removed."
        };

        map[DirectoryExposureCodes.SourceMapExposed] = new RecommendationAdvice {
            Code = DirectoryExposureCodes.SourceMapExposed,
            Title = "JavaScript source maps exposed",
            Why = "Source maps can reveal original source and comments.",
            How = "Do not publish *.map to production; adjust build pipeline or block access.",
            Links = new [] { "https://developer.chrome.com/articles/source-maps/" },
            Domain = RecommendationDomain.Http,
            Tags = new [] { "web", "javascript", "hardening" },
            Impact = "Intellectual property disclosure and easier reverse engineering.",
            Effort = RecommendationEffort.Low,
            Verify = "Requests to *.map return 403/404 and are not deployed."
        };

        map[DirectoryExposureCodes.DirectoryListingDisabled] = new RecommendationAdvice {
            Code = DirectoryExposureCodes.DirectoryListingDisabled,
            Title = "Directory browsing disabled",
            Why = "Disabling directory listing prevents disclosure of file structure and sensitive files.",
            How = "Keep directory indexes off and ensure new paths return 403/404 or custom pages.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "http", "hardening" },
            Impact = "Reduces information disclosure exposure.",
            Effort = RecommendationEffort.Low,
            Verify = "Request common directories and confirm 403/404 responses."
        };

        // Informational presence signals (coded to appear in datasets consistently)
        map[DirectoryExposureCodes.InfoSitemapPresent] = new RecommendationAdvice {
            Code = DirectoryExposureCodes.InfoSitemapPresent,
            Title = "sitemap.xml present",
            Why = "A sitemap helps crawlers discover content efficiently and is expected on many sites.",
            How = "Keep sitemap.xml up to date and ensure correct URLs; reference it in robots.txt.",
            Domain = RecommendationDomain.Other,
            Tags = new [] { "seo", "robots" },
            Impact = "Improves crawl coverage and discoverability.",
            Effort = RecommendationEffort.Low,
            Verify = "GET https://<domain>/sitemap.xml returns a valid sitemap."
        };
        map[DirectoryExposureCodes.InfoSecurityTxtPresent] = new RecommendationAdvice {
            Code = DirectoryExposureCodes.InfoSecurityTxtPresent,
            Title = "security.txt present",
            Why = "The presence of security.txt signals a vulnerability disclosure policy and contact for researchers.",
            How = "Keep the file current with valid contact and policy fields; serve over HTTPS at /.well-known/security.txt.",
            Domain = RecommendationDomain.Privacy,
            Tags = new [] { "security.txt", "vulnerability-disclosure" },
            Impact = "Facilitates responsible disclosure and reduces response time.",
            Effort = RecommendationEffort.Low,
            Verify = "GET https://<domain>/.well-known/security.txt returns policy and contact."
        };
    }
}

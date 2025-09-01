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
    }
}

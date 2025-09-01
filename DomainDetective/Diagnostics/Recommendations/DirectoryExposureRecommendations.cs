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
    }
}

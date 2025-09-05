using System.Collections.Generic;

namespace DomainDetective.Recommendations {
    internal sealed class HpkpRecommendations : IRecommendationProvider {
        public void Register(IDictionary<string, RecommendationAdvice> map) {
            map[HpkpCodes.PinsValid] = new RecommendationAdvice {
                Code = HpkpCodes.PinsValid,
                Title = "HPKP pins are valid",
                Why = "Valid pins indicate the header is syntactically correct, though HPKP is deprecated.",
                How = "Consider removing HPKP entirely or ensure pins remain current.",
                Domain = RecommendationDomain.Http,
                Tags = new[] { "hpkp", "pins" },
                Impact = "Confirms pin syntax but HPKP should generally be avoided.",
                Effort = RecommendationEffort.Low,
                Verify = "Fetch a page and confirm pins decode to 32-byte SHA-256 hashes."
            };

            map[HpkpCodes.IncludeSubDomains] = new RecommendationAdvice {
                Code = HpkpCodes.IncludeSubDomains,
                Title = "HPKP includeSubDomains set",
                Why = "Extends HPKP policy to all subdomains.",
                How = "Maintain deliberately or remove HPKP to avoid accidental outages.",
                Domain = RecommendationDomain.Http,
                Tags = new[] { "hpkp", "subdomains" },
                Impact = "Pins apply to subdomains which can increase management complexity.",
                Effort = RecommendationEffort.Low,
                Verify = "Check Public-Key-Pins header includes includeSubDomains directive."
            };
        }
    }
}

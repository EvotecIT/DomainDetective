using System.Threading.Tasks;
using DomainDetective;
using Xunit;

namespace DomainDetective.Tests {
    public class TestThreatIntelRecommendations {
        [Fact]
        public async Task EmitsPositiveRecommendations() {
            var analysis = new ThreatIntelAnalysis {
                EnableUrlHaus = false,
                GoogleSafeBrowsingOverride = _ => Task.FromResult("{}"),
                PhishTankOverride = _ => Task.FromResult("{\"results\":{\"valid\":\"true\",\"in_database\":\"false\"}}"),
                VirusTotalObjectOverride = _ => Task.FromResult<VirusTotalObject?>(new VirusTotalObject {
                    Attributes = new VirusTotalAttributes {
                        LastAnalysisStats = new VirusTotalStats { Malicious = 0 },
                        Reputation = 0
                    }
                })
            };
            await analysis.Analyze("example.com", "g", "p", "v", new InternalLogger());
            var positives = RecommendationEngine.FromPositives(analysis.Assessments);
            Assert.Contains(positives, p => p.Code == ThreatIntelCodes.NoListings);
        }
    }
}

using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Narratives;
using Xunit;

namespace DomainDetective.Tests {
    public class TestThreatIntelNarrative {
        [Fact]
        public async Task BuildsNarrativeWithPositives() {
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
            var sections = ThreatIntelNarrative.Build(analysis);
            Assert.Contains(sections.Highlights, h => h.Contains("Google Safe Browsing"));
            Assert.Contains(sections.Positives, p => p.Contains("No threats"));
        }
    }
}

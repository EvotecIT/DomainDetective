using DomainDetective.Recommendations;
using System.Collections.Generic;
using Xunit;

namespace DomainDetective.Tests {
    public class TestHpkpRecommendations {
        [Fact]
        public void RegistersPositiveCodes() {
            var map = new Dictionary<string, RecommendationAdvice>();
            new HpkpRecommendations().Register(map);
            Assert.Contains(HpkpCodes.PinsValid, map.Keys);
            Assert.Contains(HpkpCodes.IncludeSubDomains, map.Keys);
        }
    }
}

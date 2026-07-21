using System.Collections.Generic;
using DomainDetective;
using DomainDetective.Recommendations;
using Xunit;

namespace DomainDetective.Tests;

public class TestDnssecRecommendations
{
    [Fact]
    public void RegistersSuccessCodes()
    {
        var map = new Dictionary<string, RecommendationAdvice>();
        new DnssecRecommendations().Register(map);
        Assert.Contains(DnssecCodes.SignaturesValid, map.Keys);
        Assert.Contains(DnssecCodes.ChainValid, map.Keys);
    }

    [Fact]
    public void EmitsPositiveRecommendations()
    {
        var assessments = new[] {
            new Assessment {
                Severity = AssessmentSeverity.Info,
                Code = DnssecCodes.SignaturesValid,
                Message = "DNSSEC signatures are valid."
            },
            new Assessment {
                Severity = AssessmentSeverity.Info,
                Code = DnssecCodes.ChainValid,
                Message = "The DNSSEC chain is valid."
            }
        };

        var positives = RecommendationEngine.FromPositives(assessments);
        Assert.Contains(positives, p => p.Code == DnssecCodes.SignaturesValid);
        Assert.Contains(positives, p => p.Code == DnssecCodes.ChainValid);
    }
}

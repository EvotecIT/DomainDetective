using System.Linq;
using System.Threading.Tasks;
using DomainDetective.Narratives;
using DnsClientX;
using Xunit;

namespace DomainDetective.Tests;

public class TestCnameNarrative {
    private static CnameAnalysis Create() {
        return new CnameAnalysis {
            DnsConfiguration = new DnsConfiguration(),
            QueryDnsOverride = (name, type) => {
                if (type == DnsRecordType.CNAME && name == "alias.example.com") {
                    return Task.FromResult(new[] { CreateAnswer("target.example.com") });
                }
                if (type == DnsRecordType.CNAME && name == "target.example.com") {
                    return Task.FromResult(System.Array.Empty<DnsAnswer>());
                }
                if (type == DnsRecordType.A && name == "target.example.com") {
                    return Task.FromResult(new[] { CreateAnswer("192.0.2.1") });
                }
                if (type == DnsRecordType.AAAA && name == "target.example.com") {
                    return Task.FromResult(System.Array.Empty<DnsAnswer>());
                }
                return Task.FromResult(System.Array.Empty<DnsAnswer>());
            }
        };
    }

    private static DnsAnswer CreateAnswer(string data) {
        var answer = new DnsAnswer { DataRaw = data };
        var prop = typeof(DnsAnswer).GetProperty(
            "Data",
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic);
        try {
            prop?.SetValue(answer, data);
        } catch {
            // setter may be inaccessible; DataRaw provides the value
        }
        return answer;
    }

    [Fact]
    public async Task BuildsNarrativeAndRecommendations() {
        var analysis = Create();
        await analysis.Analyze("alias.example.com", new InternalLogger());
        var narrative = CnameNarrative.Build(analysis, analysis.Assessments);
        Assert.Contains("alias.example.com CNAME → target.example.com.", narrative.Highlights);
        Assert.Contains("No CNAME loop detected.", narrative.Highlights);
        var codes = analysis.Recommendations.Select(r => r.Code).ToList();
        Assert.Contains(CnameCodes.TargetResolves, codes);
        Assert.Contains(CnameCodes.NoLoop, codes);
        Assert.Contains("CNAME target resolves", narrative.Positives);
        Assert.Contains("No CNAME loop detected", narrative.Positives);
    }

    [Fact]
    public async Task AddressLookupFailureDoesNotClaimTargetDoesNotResolve() {
        var analysis = new CnameAnalysis {
            DnsConfiguration = new DnsConfiguration(),
            QueryDnsOverride = (name, type) => {
                if (type == DnsRecordType.CNAME && name == "alias.example.com") {
                    return Task.FromResult(new[] { CreateAnswer("target.example.com") });
                }
                if (type == DnsRecordType.CNAME) {
                    return Task.FromResult(System.Array.Empty<DnsAnswer>());
                }
                if (type == DnsRecordType.A) {
                    throw new System.InvalidOperationException("resolver unavailable");
                }
                return Task.FromResult(System.Array.Empty<DnsAnswer>());
            }
        };

        await analysis.Analyze("alias.example.com", new InternalLogger());

        Assert.True(analysis.CnameRecordExists);
        Assert.False(analysis.TargetResolves);
        Assert.Contains(analysis.Assessments, assessment => assessment.Code == CnameCodes.DnsLookupFailed);
        Assert.DoesNotContain(analysis.Assessments, assessment => assessment.Code == CnameCodes.TargetDoesNotResolve);
        Assert.DoesNotContain(analysis.Recommendations, recommendation => recommendation.Code == CnameCodes.TargetDoesNotResolve);
    }

    [Fact]
    public async Task NoCnameDoesNotPerformUnneededAddressQueries() {
        int cnameQueryCount = 0;
        int addressQueryCount = 0;
        var analysis = new CnameAnalysis {
            DnsConfiguration = new DnsConfiguration(),
            QueryDnsOverride = (_, type) => {
                if (type == DnsRecordType.CNAME) {
                    cnameQueryCount++;
                } else {
                    addressQueryCount++;
                }
                return Task.FromResult(System.Array.Empty<DnsAnswer>());
            }
        };

        await analysis.Analyze("direct.example.com", new InternalLogger());

        Assert.False(analysis.CnameRecordExists);
        Assert.Equal(1, cnameQueryCount);
        Assert.Equal(0, addressQueryCount);
        Assert.DoesNotContain(analysis.Assessments, assessment => assessment.Code == CnameCodes.DnsLookupFailed);
    }
}

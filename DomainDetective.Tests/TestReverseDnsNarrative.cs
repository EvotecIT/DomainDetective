using DnsClientX;
using System.Collections.Generic;
using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Narratives;
using Xunit;

namespace DomainDetective.Tests
{
    public class TestReverseDnsNarrative
    {
        private static ReverseDnsAnalysis CreateAnalysis(Dictionary<(string, DnsRecordType), DnsAnswer[]> map)
        {
            return new ReverseDnsAnalysis
            {
                DnsConfiguration = new DnsConfiguration(),
                QueryDnsOverride = (name, type) => Task.FromResult(map.TryGetValue((name, type), out var v) ? v : System.Array.Empty<DnsAnswer>())
            };
        }

        [Fact]
        public async Task BuildsNarrative()
        {
            var map = new Dictionary<(string, DnsRecordType), DnsAnswer[]>
            {
                [("mx.example.com", DnsRecordType.A)] = new[] { new DnsAnswer { DataRaw = "1.1.1.1" } },
                [("1.1.1.1.in-addr.arpa", DnsRecordType.PTR)] = new[] { new DnsAnswer { DataRaw = "mx.example.com." } }
            };
            var analysis = CreateAnalysis(map);
            await analysis.AnalyzeHosts(new[] { "mx.example.com" });
            var sections = ReverseDnsNarrative.Build(analysis);
            Assert.Contains(sections.Highlights, h => h.Contains("PTR records found"));
            Assert.Contains(sections.Highlights, h => h.Contains("align"));
            Assert.Contains(sections.Highlights, h => h.Contains("resolve back"));
        }

        [Fact]
        public void GeneratesPositiveAdvice()
        {
            var assessments = new List<Assessment>
            {
                new Assessment { Code = ReverseDnsCodes.PtrRecordPresent, Severity = AssessmentSeverity.Info },
                new Assessment { Code = ReverseDnsCodes.PtrMatchesMx, Severity = AssessmentSeverity.Info },
                new Assessment { Code = ReverseDnsCodes.ForwardConfirmed, Severity = AssessmentSeverity.Info }
            };
            var positives = RecommendationEngine.FromPositives(assessments);
            Assert.Contains(positives, p => p.Code == ReverseDnsCodes.PtrRecordPresent);
            Assert.Contains(positives, p => p.Code == ReverseDnsCodes.PtrMatchesMx);
            Assert.Contains(positives, p => p.Code == ReverseDnsCodes.ForwardConfirmed);
        }
    }
}

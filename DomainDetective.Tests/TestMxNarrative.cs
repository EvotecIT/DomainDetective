using DnsClientX;
using System.Collections.Generic;
using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Narratives;
using Xunit;

namespace DomainDetective.Tests
{
    public class TestMxNarrative
    {
        private static MXAnalysis CreateAnalysis()
        {
            var map = new Dictionary<(string, DnsRecordType), DnsAnswer[]>
            {
                [("mail1.example.com", DnsRecordType.A)] = new[] { new DnsAnswer { DataRaw = "1.1.1.1" } },
                [("mail1.example.com", DnsRecordType.AAAA)] = System.Array.Empty<DnsAnswer>(),
                [("mail2.example.com", DnsRecordType.A)] = new[] { new DnsAnswer { DataRaw = "2.2.2.2" } },
                [("mail2.example.com", DnsRecordType.AAAA)] = new[] { new DnsAnswer { DataRaw = "2001::1" } }
            };
            return new MXAnalysis
            {
                DnsConfiguration = new DnsConfiguration(),
                QueryDnsOverride = (name, type) => Task.FromResult(map.TryGetValue((name, type), out var v) ? v : System.Array.Empty<DnsAnswer>())
            };
        }

        [Fact]
        public async Task BuildsNarrative()
        {
            var answers = new List<DnsAnswer>
            {
                new DnsAnswer { DataRaw = "10 mail1.example.com", Type = DnsRecordType.MX },
                new DnsAnswer { DataRaw = "20 mail2.example.com", Type = DnsRecordType.MX }
            };
            var analysis = CreateAnalysis();
            await analysis.AnalyzeMxRecords(answers, new InternalLogger());
            var sections = MxNarrative.Build(analysis);
            Assert.Contains(sections.Highlights, h => h.Contains("MX records: 2"));
            Assert.Contains(sections.Highlights, h => h.Contains("ascending order"));
            Assert.Contains(sections.Highlights, h => h.Contains("IPv6"));
        }

        [Fact]
        public void GeneratesPositiveAdvice()
        {
            var assessments = new List<Assessment>
            {
                new Assessment { Code = MxCodes.RedundantHosts, Severity = AssessmentSeverity.Info },
                new Assessment { Code = MxCodes.TlsSupported, Severity = AssessmentSeverity.Info }
            };
            var positives = RecommendationEngine.FromPositives(assessments);
            Assert.Contains(positives, p => p.Code == MxCodes.RedundantHosts);
            Assert.Contains(positives, p => p.Code == MxCodes.TlsSupported);
        }
    }
}

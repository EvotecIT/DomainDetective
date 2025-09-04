using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using DomainDetective.Narratives;
using DnsClientX;
using Xunit;

namespace DomainDetective.Tests
{
    public class TestIpNeighborNarrative
    {
        private static DnsAnswer CreateAnswer(string data)
        {
            var answer = new DnsAnswer { DataRaw = data };
            var prop = typeof(DnsAnswer).GetProperty(
                "Data",
                System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic);
            try
            {
                prop?.SetValue(answer, data);
            }
            catch
            {
            }
            return answer;
        }

        [Fact]
        public async Task NarrativeSummarizesNeighborsAndPositives()
        {
            var analysis = new IPNeighborAnalysis
            {
                DnsConfiguration = new DnsConfiguration(),
                QueryDnsOverride = (name, type) =>
                {
                    if (type == DnsRecordType.A) return Task.FromResult(new[] { CreateAnswer("1.1.1.1") });
                    if (type == DnsRecordType.PTR) return Task.FromResult(new[] { CreateAnswer("ptr.example.com.") });
                    return Task.FromResult(Array.Empty<DnsAnswer>());
                },
                PassiveDnsLookupOverride = _ => Task.FromResult(new List<string>()),
                RPKIValidationOverride = _ => Task.FromResult(true)
            };

            await analysis.Analyze("example.com", new InternalLogger());
            var narrative = IpNeighborNarrative.Build(analysis);
            Assert.Contains("1.1.1.1", narrative.Highlights.First());
            var codes = analysis.Recommendations.Select(r => r.Code).ToList();
            Assert.Contains(IpNeighborCodes.NoMaliciousNeighbors, codes);
            Assert.Contains("No malicious neighbors detected", narrative.Positives);
        }
    }
}


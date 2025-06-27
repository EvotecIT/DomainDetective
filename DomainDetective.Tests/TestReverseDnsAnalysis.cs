using DnsClientX;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestReverseDnsAnalysis {
        private static ReverseDnsAnalysis CreateAnalysis(Dictionary<(string, DnsRecordType), DnsAnswer[]> map) {
            return new ReverseDnsAnalysis {
                DnsConfiguration = new DnsConfiguration(),
                QueryDnsOverride = (name, type) => Task.FromResult(map.TryGetValue((name, type), out var v) ? v : Array.Empty<DnsAnswer>())
            };
        }

        [Fact]
        public async Task ValidPtrRecord() {
            var map = new Dictionary<(string, DnsRecordType), DnsAnswer[]> {
                [("mail.example.com", DnsRecordType.A)] = new[] { new DnsAnswer { DataRaw = "1.1.1.1" } },
                [("1.1.1.1.in-addr.arpa", DnsRecordType.PTR)] = new[] { new DnsAnswer { DataRaw = "mail.example.com." } }
            };
            var analysis = CreateAnalysis(map);
            await analysis.AnalyzeHosts(new[] { "mail.example.com" });
            var result = Assert.Single(analysis.Results);
            Assert.True(result.IsValid);
            Assert.Equal("mail.example.com", result.ExpectedHost);
        }

        [Fact]
        public async Task InvalidPtrRecord() {
            var map = new Dictionary<(string, DnsRecordType), DnsAnswer[]> {
                [("mail.example.com", DnsRecordType.A)] = new[] { new DnsAnswer { DataRaw = "1.1.1.2" } },
                [("1.1.1.2.in-addr.arpa", DnsRecordType.PTR)] = new[] { new DnsAnswer { DataRaw = "other.example.com." } }
            };
            var analysis = CreateAnalysis(map);
            await analysis.AnalyzeHosts(new[] { "mail.example.com" });
            var result = Assert.Single(analysis.Results);
            Assert.False(result.IsValid);
            Assert.Equal("mail.example.com", result.ExpectedHost);
        }
    }
}

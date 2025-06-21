using DnsClientX;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestNSAnalysis {
        private static NSAnalysis CreateAnalysis(Func<string, DnsRecordType, Task<DnsAnswer[]>>? overrideFunc = null) {
            return new NSAnalysis {
                DnsConfiguration = new DnsConfiguration(),
                QueryDnsOverride = overrideFunc
            };
        }

        [Fact]
        public async Task DetectAtLeastTwoRecords() {
            var answers = new List<DnsAnswer> {
                new DnsAnswer { DataRaw = "ns1.example.com", Type = DnsRecordType.NS },
                new DnsAnswer { DataRaw = "ns2.example.com", Type = DnsRecordType.NS }
            };
            var analysis = CreateAnalysis((_, _) => Task.FromResult(Array.Empty<DnsAnswer>()));
            await analysis.AnalyzeNsRecords(answers, new InternalLogger());

            Assert.True(analysis.AtLeastTwoRecords);
            Assert.False(analysis.HasDuplicates);
        }

        [Fact]
        public async Task DetectDuplicates() {
            var answers = new List<DnsAnswer> {
                new DnsAnswer { DataRaw = "ns1.example.com", Type = DnsRecordType.NS },
                new DnsAnswer { DataRaw = "ns1.example.com", Type = DnsRecordType.NS }
            };
            var analysis = CreateAnalysis((_, _) => Task.FromResult(Array.Empty<DnsAnswer>()));
            await analysis.AnalyzeNsRecords(answers, new InternalLogger());

            Assert.True(analysis.HasDuplicates);
        }

        [Fact]
        public async Task DetectMissingARecord() {
            var answers = new List<DnsAnswer> {
                new DnsAnswer { DataRaw = "ns1.example.com", Type = DnsRecordType.NS }
            };
            var analysis = CreateAnalysis((name, type) => Task.FromResult(Array.Empty<DnsAnswer>()));
            await analysis.AnalyzeNsRecords(answers, new InternalLogger());

            Assert.False(analysis.AllHaveAOrAaaa);
        }

        [Fact]
        public async Task DetectCname() {
            var answers = new List<DnsAnswer> {
                new DnsAnswer { DataRaw = "ns1.example.com", Type = DnsRecordType.NS }
            };
            var analysis = CreateAnalysis((name, type) => {
                if (type == DnsRecordType.CNAME) {
                    return Task.FromResult(new[] { new DnsAnswer { DataRaw = "cname.example.com" } });
                }
                return Task.FromResult(Array.Empty<DnsAnswer>());
            });
            await analysis.AnalyzeNsRecords(answers, new InternalLogger());

            Assert.True(analysis.PointsToCname);
        }
    }
}

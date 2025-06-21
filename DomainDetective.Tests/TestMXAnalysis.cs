using DnsClientX;
using System.Collections.Generic;

namespace DomainDetective.Tests {
    public class TestMXAnalysis {
        private static MXAnalysis CreateAnalysis() {
            return new MXAnalysis {
                DnsConfiguration = new DnsConfiguration(),
                QueryDnsOverride = (_, _) => Task.FromResult(Array.Empty<DnsAnswer>())
            };
        }

        [Fact]
        public async Task DetectProperOrder() {
            var answers = new List<DnsAnswer> {
                new DnsAnswer { DataRaw = "10 mail1.example.com", Type = DnsRecordType.MX },
                new DnsAnswer { DataRaw = "20 mail2.example.com", Type = DnsRecordType.MX }
            };
            var analysis = CreateAnalysis();
            await analysis.AnalyzeMxRecords(answers, new InternalLogger());

            Assert.True(analysis.PrioritiesInOrder);
            Assert.True(analysis.HasBackupServers);
        }

        [Fact]
        public async Task DetectOutOfOrder() {
            var answers = new List<DnsAnswer> {
                new DnsAnswer { DataRaw = "20 mail2.example.com", Type = DnsRecordType.MX },
                new DnsAnswer { DataRaw = "10 mail1.example.com", Type = DnsRecordType.MX }
            };
            var analysis = CreateAnalysis();
            await analysis.AnalyzeMxRecords(answers, new InternalLogger());

            Assert.False(analysis.PrioritiesInOrder);
        }

        [Fact]
        public async Task DetectNoBackup() {
            var answers = new List<DnsAnswer> {
                new DnsAnswer { DataRaw = "10 mail1.example.com", Type = DnsRecordType.MX },
                new DnsAnswer { DataRaw = "10 mail2.example.com", Type = DnsRecordType.MX }
            };
            var analysis = CreateAnalysis();
            await analysis.AnalyzeMxRecords(answers, new InternalLogger());

            Assert.False(analysis.HasBackupServers);
        }
    }
}

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

        [Fact]
        public async Task ValidateConfigurationReturnsTrue() {
            var answers = new List<DnsAnswer> {
                new DnsAnswer { DataRaw = "10 mail1.example.com", Type = DnsRecordType.MX }
            };
            var analysis = new MXAnalysis {
                DnsConfiguration = new DnsConfiguration(),
                QueryDnsOverride = (name, type) => {
                    return type switch {
                        DnsRecordType.A => Task.FromResult(new[] { new DnsAnswer { DataRaw = "1.1.1.1" } }),
                        DnsRecordType.AAAA => Task.FromResult(new[] { new DnsAnswer { DataRaw = "2001::1" } }),
                        _ => Task.FromResult(Array.Empty<DnsAnswer>())
                    };
                }
            };
            await analysis.AnalyzeMxRecords(answers, new InternalLogger());

            Assert.True(analysis.ValidateMxConfiguration());
            Assert.True(analysis.ValidMxConfiguration);
        }

        [Fact]
        public async Task ValidateConfigurationDetectsIp() {
            var answers = new List<DnsAnswer> {
                new DnsAnswer { DataRaw = "10 192.168.1.1", Type = DnsRecordType.MX }
            };
            var analysis = CreateAnalysis();
            await analysis.AnalyzeMxRecords(answers, new InternalLogger());

            Assert.False(analysis.ValidateMxConfiguration());
            Assert.False(analysis.ValidMxConfiguration);
            Assert.True(analysis.PointsToIpAddress);
        }
    }
}

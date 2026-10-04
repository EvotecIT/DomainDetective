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

        [Fact]
        public async Task DetectStableOrderingWithDuplicates() {
            var answers = new List<DnsAnswer> {
                new DnsAnswer { DataRaw = "10 mail1.example.com", Type = DnsRecordType.MX },
                new DnsAnswer { DataRaw = "20 mail2.example.com", Type = DnsRecordType.MX },
                new DnsAnswer { DataRaw = "20 mail3.example.com", Type = DnsRecordType.MX }
            };
            var analysis = CreateAnalysis();
            await analysis.AnalyzeMxRecords(answers, new InternalLogger());

            Assert.True(analysis.PrioritiesInOrder);
        }

        [Fact]
        public async Task DetectOutOfOrderWithDuplicate() {
            var answers = new List<DnsAnswer> {
                new DnsAnswer { DataRaw = "10 mail1.example.com", Type = DnsRecordType.MX },
                new DnsAnswer { DataRaw = "20 mail2.example.com", Type = DnsRecordType.MX },
                new DnsAnswer { DataRaw = "10 mail3.example.com", Type = DnsRecordType.MX }
            };
            var analysis = CreateAnalysis();
            await analysis.AnalyzeMxRecords(answers, new InternalLogger());

            Assert.False(analysis.PrioritiesInOrder);
        }

        [Fact]
        public async Task EvaluatesUniqueHostsInAscendingOrder() {
            var answers = new List<DnsAnswer> {
                new DnsAnswer { DataRaw = "20 mail2.example.com", Type = DnsRecordType.MX },
                new DnsAnswer { DataRaw = "10 mail1.example.com", Type = DnsRecordType.MX },
                new DnsAnswer { DataRaw = "10 mail1.example.com", Type = DnsRecordType.MX },
                new DnsAnswer { DataRaw = "30 mail3.example.com", Type = DnsRecordType.MX }
            };

            var queriedHosts = new List<string>();
            var analysis = new MXAnalysis {
                DnsConfiguration = new DnsConfiguration(),
                QueryDnsOverride = (name, type) => {
                    if (type == DnsRecordType.CNAME) {
                        queriedHosts.Add(name);
                    }

                    return Task.FromResult(Array.Empty<DnsAnswer>());
                }
            };

            await analysis.AnalyzeMxRecords(answers, new InternalLogger());

            Assert.Equal(new[] { "mail1.example.com", "mail2.example.com", "mail3.example.com" }, queriedHosts);
        }

        [Fact]
        public async Task ReportsMissingAddressesForEachMxHost() {
            var analysis = new MXAnalysis {
                Subject = "example.com",
                QueryDnsOverride = (_, type) => Task.FromResult(type == DnsRecordType.NS
                    ? new[] { new DnsAnswer { Type = DnsRecordType.NS, DataRaw = "ns.example.com" } }
                    : Array.Empty<DnsAnswer>())
            };
            analysis.DnsConfiguration.QueryDnsOverride = (_, _) => Task.FromResult(Array.Empty<DnsAnswer>());
            var logger = new InternalLogger();
            int publicWarnings = 0;
            logger.OnWarningMessage += (_, e) => {
                if (e.Code == MxCodes.TargetNoAddressRecords) {
                    publicWarnings++;
                }
            };

            await analysis.AnalyzeMxRecords(new[] {
                new DnsAnswer { DataRaw = "10 mail1.example.com", Type = DnsRecordType.MX },
                new DnsAnswer { DataRaw = "20 mail2.example.com", Type = DnsRecordType.MX }
            }, logger);

            var targets = analysis.Assessments
                .Where(assessment => assessment.Code == MxCodes.TargetNoAddressRecords)
                .Select(assessment => assessment.Target)
                .OrderBy(target => target)
                .ToArray();
            Assert.Equal(new[] { "mail1.example.com", "mail2.example.com" }, targets);
            Assert.Equal(1, publicWarnings);
        }
    }}

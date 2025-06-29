using DnsClientX;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestNSAnalysis {
        private static NSAnalysis CreateAnalysis(
            Func<string, DnsRecordType, Task<DnsAnswer[]>>? overrideFunc = null,
            Func<string, DnsRecordType, Task<IEnumerable<DnsResponse>>>? fullOverride = null) {
            return new NSAnalysis {
                DnsConfiguration = new DnsConfiguration(),
                QueryDnsOverride = overrideFunc,
                QueryDnsFullOverride = fullOverride
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

        [Fact]
        public async Task DetectDiverseLocations() {
            var answers = new List<DnsAnswer> {
                new DnsAnswer { DataRaw = "ns1.example.com", Type = DnsRecordType.NS },
                new DnsAnswer { DataRaw = "ns2.example.com", Type = DnsRecordType.NS }
            };
            var analysis = CreateAnalysis((name, type) => {
                return (name, type) switch {
                    ("ns1.example.com", DnsRecordType.A) => Task.FromResult(new[] { new DnsAnswer { DataRaw = "1.1.1.1" } }),
                    ("ns2.example.com", DnsRecordType.A) => Task.FromResult(new[] { new DnsAnswer { DataRaw = "2.2.2.2" } }),
                    _ => Task.FromResult(Array.Empty<DnsAnswer>())
                };
            });
            await analysis.AnalyzeNsRecords(answers, new InternalLogger());

            Assert.True(analysis.HasDiverseLocations);
        }

        [Fact]
        public async Task DetectSingleSubnet() {
            var answers = new List<DnsAnswer> {
                new DnsAnswer { DataRaw = "ns1.example.com", Type = DnsRecordType.NS },
                new DnsAnswer { DataRaw = "ns2.example.com", Type = DnsRecordType.NS }
            };
            var analysis = CreateAnalysis((name, type) => {
                return (name, type) switch {
                    (_, DnsRecordType.A) => Task.FromResult(new[] { new DnsAnswer { DataRaw = "1.1.1.1" } }),
                    _ => Task.FromResult(Array.Empty<DnsAnswer>())
                };
            });
            await analysis.AnalyzeNsRecords(answers, new InternalLogger());

            Assert.False(analysis.HasDiverseLocations);
        }

        [Fact]
        public async Task DetectDelegationMismatch() {
            var childAnswers = new List<DnsAnswer> {
                new DnsAnswer { DataRaw = "ns1.example.com", Type = DnsRecordType.NS }
            };
            var analysis = CreateAnalysis(
                overrideFunc: (_, _) => Task.FromResult(Array.Empty<DnsAnswer>()),
                fullOverride: (_, _) => Task.FromResult<IEnumerable<DnsResponse>>(new[] {
                    new DnsResponse {
                        Answers = new[] { new DnsAnswer { DataRaw = "ns2.example.com", Type = DnsRecordType.NS } },
                        Additional = Array.Empty<DnsAnswer>()
                    }
                }));
            await analysis.AnalyzeNsRecords(childAnswers, new InternalLogger());
            await analysis.AnalyzeParentDelegation("example.com", new InternalLogger());

            Assert.False(analysis.DelegationMatches);
        }

        [Fact]
        public async Task DetectMissingGlue() {
            var childAnswers = new List<DnsAnswer> {
                new DnsAnswer { DataRaw = "ns1.example.com", Type = DnsRecordType.NS }
            };
            var analysis = CreateAnalysis(
                overrideFunc: (_, _) => Task.FromResult(Array.Empty<DnsAnswer>()),
                fullOverride: (_, _) => Task.FromResult<IEnumerable<DnsResponse>>(new[] {
                    new DnsResponse {
                        Answers = new[] { new DnsAnswer { DataRaw = "ns1.example.com", Type = DnsRecordType.NS } },
                        Additional = Array.Empty<DnsAnswer>()
                    }
                }));
            await analysis.AnalyzeNsRecords(childAnswers, new InternalLogger());
            await analysis.AnalyzeParentDelegation("example.com", new InternalLogger());

            Assert.False(analysis.GlueRecordsComplete);
        }

        [Fact]
        public async Task DetectInconsistentGlue() {
            var childAnswers = new List<DnsAnswer> {
                new DnsAnswer { DataRaw = "ns1.example.com", Type = DnsRecordType.NS }
            };
            var analysis = CreateAnalysis(
                overrideFunc: (name, type) => {
                    if (name == "ns1.example.com" && (type == DnsRecordType.A || type == DnsRecordType.AAAA)) {
                        return Task.FromResult(new[] { new DnsAnswer { DataRaw = "2.2.2.2" } });
                    }
                    return Task.FromResult(Array.Empty<DnsAnswer>());
                },
                fullOverride: (_, _) => Task.FromResult<IEnumerable<DnsResponse>>(new[] {
                    new DnsResponse {
                        Answers = new[] { new DnsAnswer { DataRaw = "ns1.example.com", Type = DnsRecordType.NS } },
                        Additional = new[] { new DnsAnswer { Name = "ns1.example.com", DataRaw = "1.1.1.1", Type = DnsRecordType.A } }
                    }
                }));
            await analysis.AnalyzeNsRecords(childAnswers, new InternalLogger());
            await analysis.AnalyzeParentDelegation("example.com", new InternalLogger());

            Assert.False(analysis.GlueRecordsConsistent);
        }

        [Fact]
        public async Task QueryRootServersRespond() {
            var analysis = CreateAnalysis((name, type) => {
                if (name == "." && type == DnsRecordType.NS) {
                    return Task.FromResult(new[] {
                        new DnsAnswer { DataRaw = "a.root-servers.net" },
                        new DnsAnswer { DataRaw = "b.root-servers.net" }
                    });
                }
                if (name == "a.root-servers.net" && type == DnsRecordType.A) {
                    return Task.FromResult(new[] { new DnsAnswer { DataRaw = "1.1.1.1" } });
                }
                return Task.FromResult(Array.Empty<DnsAnswer>());
            });
            await analysis.QueryRootServers(new InternalLogger());
            Assert.True(analysis.RootServerResponses["a.root-servers.net"]);
            Assert.False(analysis.RootServerResponses["b.root-servers.net"]);
        }

        [Fact]
        public async Task DetectRecursionEnabled() {
            var answers = new List<DnsAnswer> {
                new DnsAnswer { DataRaw = "ns1.example.com", Type = DnsRecordType.NS }
            };
            var analysis = CreateAnalysis((_, _) => Task.FromResult(Array.Empty<DnsAnswer>()));
            analysis.RecursionTestOverride = _ => Task.FromResult(true);
            await analysis.AnalyzeNsRecords(answers, new InternalLogger());
            await analysis.TestRecursion(new InternalLogger());
            Assert.True(analysis.RecursionEnabled["ns1.example.com"]);
        }
    }
}
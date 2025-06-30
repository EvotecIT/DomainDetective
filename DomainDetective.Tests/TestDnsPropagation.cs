using DnsClientX;
using DomainDetective;
using System.Net;
using System.Threading;
using System.Linq;
namespace DomainDetective.Tests {
    public class TestDnsPropagation {
        [Fact]
        public void LoadServersAddsEntries() {
            var file = "Data/DNS/PublicDNS.json";
            var analysis = new DnsPropagationAnalysis();
            analysis.LoadServers(file, clearExisting: true);
            Assert.NotEmpty(analysis.Servers);
        }

        [Fact]
        public void AddAndRemoveServerWorks() {
            var analysis = new DnsPropagationAnalysis();
            var entry = new PublicDnsEntry { IPAddress = "1.1.1.1", Country = "Test" };
            analysis.AddServer(entry);
            Assert.Contains(analysis.Servers, s => s.IPAddress == "1.1.1.1");
            analysis.RemoveServer("1.1.1.1");
            Assert.DoesNotContain(analysis.Servers, s => s.IPAddress == "1.1.1.1");
        }

        [Fact]
        public async Task QueryHandlesDownServer() {
            var analysis = new DnsPropagationAnalysis();
            analysis.AddServer(new PublicDnsEntry { IPAddress = "192.0.2.1", Country = "Test" });
            var results = await analysis.QueryAsync("example.com", DnsRecordType.A, analysis.Servers);
            Assert.Single(results);
            Assert.False(results[0].Success);
        }

        [Fact]
        public async Task QueryHonorsCancellation() {
            var analysis = new DnsPropagationAnalysis();
            analysis.AddServer(new PublicDnsEntry { IPAddress = "192.0.2.1", Country = "Test" });
            using var cts = new CancellationTokenSource();
            cts.Cancel();

            await Assert.ThrowsAsync<OperationCanceledException>(async () =>
                await analysis.QueryAsync("example.com", DnsRecordType.A, analysis.Servers, cts.Token));
        }

        [Fact]
        public async Task QueryReturnsEmptyWhenNoServers() {
            var analysis = new DnsPropagationAnalysis();
            var results = await analysis.QueryAsync("example.com", DnsRecordType.A, Enumerable.Empty<PublicDnsEntry>());
            Assert.Empty(results);
        }

        [Fact]
        public void CompareResultsGroupsByRecordSet() {
            var results = new[] {
                new DnsPropagationResult {
                    Server = new PublicDnsEntry { IPAddress = "1.1.1.1" },
                    RecordType = DnsRecordType.A,
                    Records = new[] { "1.1.1.1" },
                    Success = true
                },
                new DnsPropagationResult {
                    Server = new PublicDnsEntry { IPAddress = "8.8.8.8" },
                    RecordType = DnsRecordType.A,
                    Records = new[] { "1.1.1.1" },
                    Success = true
                },
                new DnsPropagationResult {
                    Server = new PublicDnsEntry { IPAddress = "9.9.9.9" },
                    RecordType = DnsRecordType.A,
                    Records = new[] { "2.2.2.2" },
                    Success = true
                }
            };

            var groups = DnsPropagationAnalysis.CompareResults(results);
            Assert.Equal(2, groups.Count);
            Assert.Contains(groups, g => g.Value.Any(s => s.IPAddress == "9.9.9.9"));
        }

        [Fact]
        public void CompareResultsHandlesIpv6Variants() {
            var results = new[] {
                new DnsPropagationResult {
                    Server = new PublicDnsEntry { IPAddress = "1.1.1.1" },
                    RecordType = DnsRecordType.AAAA,
                    Records = new[] { "2001:0db8:0000:0000:0000:0000:0000:0001" },
                    Success = true
                },
                new DnsPropagationResult {
                    Server = new PublicDnsEntry { IPAddress = "8.8.8.8" },
                    RecordType = DnsRecordType.AAAA,
                    Records = new[] { "2001:db8::1" },
                    Success = true
                }
            };

            var groups = DnsPropagationAnalysis.CompareResults(results);
            Assert.Single(groups);
            Assert.Equal(2, groups.First().Value.Count);
            Assert.Equal(IPAddress.Parse("2001:db8::1").ToString(), groups.Keys.First());
        }

        [Fact]
        public void CompareResultsConsistentKeyCasing() {
            var results = new[] {
                new DnsPropagationResult {
                    Server = new PublicDnsEntry { IPAddress = "1.1.1.1" },
                    RecordType = DnsRecordType.AAAA,
                    Records = new[] { "2001:DB8::1" },
                    Success = true
                },
                new DnsPropagationResult {
                    Server = new PublicDnsEntry { IPAddress = "8.8.8.8" },
                    RecordType = DnsRecordType.AAAA,
                    Records = new[] { "2001:db8::1" },
                    Success = true
                }
            };

            var groups = DnsPropagationAnalysis.CompareResults(results);
            Assert.Single(groups);
            Assert.Equal(2, groups.First().Value.Count);
            Assert.Equal("2001:db8::1", groups.Keys.First());
        }

        [Fact]
        public void CompareResultsGroupsTextRecordsCaseInsensitive() {
            var results = new[] {
                new DnsPropagationResult {
                    Server = new PublicDnsEntry { IPAddress = "1.1.1.1" },
                    RecordType = DnsRecordType.TXT,
                    Records = new[] { "Example" },
                    Success = true
                },
                new DnsPropagationResult {
                    Server = new PublicDnsEntry { IPAddress = "8.8.8.8" },
                    RecordType = DnsRecordType.TXT,
                    Records = new[] { "example" },
                    Success = true
                }
            };

            var groups = DnsPropagationAnalysis.CompareResults(results);
            Assert.Single(groups);
            Assert.Equal(2, groups.First().Value.Count);
            Assert.Equal("example", groups.Keys.First());
        }

        [Fact]
        public void CompareResultsIgnoresNullRecords() {
            var results = new[] {
                new DnsPropagationResult {
                    Server = new PublicDnsEntry { IPAddress = "1.1.1.1" },
                    RecordType = DnsRecordType.A,
                    Records = null,
                    Success = true
                }
            };

            var exception = Record.Exception(() => DnsPropagationAnalysis.CompareResults(results));
            Assert.Null(exception);
        }

        [Fact]
        public void LoadServersTrimsWhitespace() {
            var json = "[{\"Country\":\" Test \",\"IPAddress\":\"1.2.3.4\",\"HostName\":\" example.com \",\"Location\":\" Somewhere \",\"ASN\":\"123\",\"ASNName\":\" Example ASN \"}]";

            var file = Path.GetTempFileName();
            try {
                File.WriteAllText(file, json);

                var analysis = new DnsPropagationAnalysis();
                analysis.LoadServers(file, clearExisting: true);

                var server = Assert.Single(analysis.Servers);
                Assert.Equal("Test", server.Country);
                Assert.Equal("example.com", server.HostName);
                Assert.Equal("Somewhere", server.Location);
                Assert.Equal("Example ASN", server.ASNName);
            }
            finally {
                File.Delete(file);
            }
        }

        [Theory]
        [InlineData("300.1.1.1")]
        [InlineData("not.an.ip")]
        [InlineData("1.2.3")]
        public void AddServerThrowsForInvalidAddress(string address) {
            var analysis = new DnsPropagationAnalysis();
            var entry = new PublicDnsEntry { IPAddress = address };
            Assert.Throws<FormatException>(() => analysis.AddServer(entry));
        }

        [Fact]
        public void LoadServersThrowsForInvalidAddress() {
            var json = "[{\"IPAddress\":\"bad.ip\"}]";
            var file = Path.GetTempFileName();
            try {
                File.WriteAllText(file, json);
                var analysis = new DnsPropagationAnalysis();
                Assert.Throws<FormatException>(() => analysis.LoadServers(file, clearExisting: true));
            }
            finally {
                File.Delete(file);
            }
        }

        [Theory]
        [InlineData("2001:db8:0:0:0:0:0:1")]
        [InlineData("2001:db8:0:0::1")]
        public void AddServerThrowsForNonCanonicalIpv6(string address) {
            var analysis = new DnsPropagationAnalysis();
            var entry = new PublicDnsEntry { IPAddress = address };
            Assert.Throws<FormatException>(() => analysis.AddServer(entry));
        }

        [Fact]
        public void CompareResultsHandlesIpv6ZoneIndex() {
            var results = new[] {
                new DnsPropagationResult {
                    Server = new PublicDnsEntry { IPAddress = "1.1.1.1" },
                    RecordType = DnsRecordType.AAAA,
                    Records = new[] { "fe80::1%2" },
                    Success = true
                },
                new DnsPropagationResult {
                    Server = new PublicDnsEntry { IPAddress = "8.8.8.8" },
                    RecordType = DnsRecordType.AAAA,
                    Records = new[] { "fe80:0:0:0:0:0:0:1%2" },
                    Success = true
                }
            };

            var groups = DnsPropagationAnalysis.CompareResults(results);
            Assert.Single(groups);
            Assert.Equal(2, groups.First().Value.Count);
            Assert.Equal(IPAddress.Parse("fe80::1%2").ToString(), groups.Keys.First());
        }
    }
}
using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestReverseDnsAnalysis {
        private static ReverseDnsAnalysis CreateAnalysis(
            Dictionary<(string, DnsRecordType), DnsAnswer[]> map,
            Dictionary<(string, DnsRecordType), IEnumerable<DnsResponse>>? full = null) {
            return new ReverseDnsAnalysis {
                DnsConfiguration = new DnsConfiguration(),
                QueryDnsOverride = (name, type) => Task.FromResult(map.TryGetValue((name, type), out var v) ? v : Array.Empty<DnsAnswer>()),
                QueryDnsFullOverride = full == null ? null :
                    new Func<string, DnsRecordType, Task<IEnumerable<DnsResponse>>>((name, type) =>
                        Task.FromResult(full.TryGetValue((name, type), out var r) ? r : Enumerable.Empty<DnsResponse>()))
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
            Assert.True(result.FcrDnsValid);
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
            Assert.False(result.FcrDnsValid);
            Assert.Equal("mail.example.com", result.ExpectedHost);
        }

        [Fact]
        public async Task FcrDnsForwardConfirmation() {
            var map = new Dictionary<(string, DnsRecordType), DnsAnswer[]> {
                [("mail.example.com", DnsRecordType.A)] = new[] { new DnsAnswer { DataRaw = "1.1.1.1" } },
                [("1.1.1.1.in-addr.arpa", DnsRecordType.PTR)] = new[] { new DnsAnswer { DataRaw = "mail.example.com." } }
            };
            var analysis = CreateAnalysis(map);
            await analysis.AnalyzeHosts(new[] { "mail.example.com" });
            var result = Assert.Single(analysis.Results);
            Assert.True(result.FcrDnsValid);
        }

        [Fact]
        public async Task FcrDnsForwardMismatch() {
            var map = new Dictionary<(string, DnsRecordType), DnsAnswer[]> {
                [("mail.example.com", DnsRecordType.A)] = new[] { new DnsAnswer { DataRaw = "1.1.1.1" } },
                [("1.1.1.1.in-addr.arpa", DnsRecordType.PTR)] = new[] { new DnsAnswer { DataRaw = "ptr.example.com." } },
                [("ptr.example.com", DnsRecordType.A)] = new[] { new DnsAnswer { DataRaw = "9.9.9.9" } }
            };
            var analysis = CreateAnalysis(map);
            await analysis.AnalyzeHosts(new[] { "mail.example.com" });
            var result = Assert.Single(analysis.Results);
            Assert.False(result.FcrDnsValid);
        }

        [Fact]
        public async Task RetryOnTruncatedIpv6Ptr() {
            var ip = IPAddress.Parse("2001::1");
            var ptrName = ip.ToPtrFormat() + ".ip6.arpa";
            var map = new Dictionary<(string, DnsRecordType), DnsAnswer[]> {
                [("mail.example.com", DnsRecordType.AAAA)] = new[] { new DnsAnswer { DataRaw = ip.ToString() } },
                [("mail.example.com", DnsRecordType.A)] = Array.Empty<DnsAnswer>(),
                [(ptrName, DnsRecordType.PTR)] = new[] { new DnsAnswer { DataRaw = "mail.example.com." } }
            };
            var full = new Dictionary<(string, DnsRecordType), IEnumerable<DnsResponse>> {
                [(ptrName, DnsRecordType.PTR)] = new[] { new DnsResponse { IsTruncated = true, Answers = Array.Empty<DnsAnswer>() } }
            };
            var analysis = CreateAnalysis(map, full);
            await analysis.AnalyzeHosts(new[] { "mail.example.com" });
            var result = Assert.Single(analysis.Results);
            Assert.Equal("mail.example.com", result.PtrRecord);
        }

        [Fact]
        public async Task MalformedPtrRecordIgnored() {
            var map = new Dictionary<(string, DnsRecordType), DnsAnswer[]> {
                [("mail.example.com", DnsRecordType.A)] = new[] { new DnsAnswer { DataRaw = "1.1.1.3" } },
                [("1.1.1.3.in-addr.arpa", DnsRecordType.PTR)] = new[] { new DnsAnswer { DataRaw = "bad_host" } }
            };
            var analysis = CreateAnalysis(map);
            await analysis.AnalyzeHosts(new[] { "mail.example.com" });
            var result = Assert.Single(analysis.Results);
            Assert.Null(result.PtrRecord);
            Assert.False(result.IsValid);
            Assert.False(result.FcrDnsValid);
        }
    }
}

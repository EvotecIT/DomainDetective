using DnsClientX;
using DomainDetective;
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
        public void CompareResultsGroupsByRecordSet() {
            var results = new[] {
                new DnsPropagationResult {
                    Server = new PublicDnsEntry { IPAddress = "1.1.1.1" },
                    Records = new[] { "1.1.1.1" },
                    Success = true
                },
                new DnsPropagationResult {
                    Server = new PublicDnsEntry { IPAddress = "8.8.8.8" },
                    Records = new[] { "1.1.1.1" },
                    Success = true
                },
                new DnsPropagationResult {
                    Server = new PublicDnsEntry { IPAddress = "9.9.9.9" },
                    Records = new[] { "2.2.2.2" },
                    Success = true
                }
            };

            var groups = DnsPropagationAnalysis.CompareResults(results);
            Assert.Equal(2, groups.Count);
            Assert.Contains(groups, g => g.Value.Any(s => s.IPAddress == "9.9.9.9"));
        }
    }
}

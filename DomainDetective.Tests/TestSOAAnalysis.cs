using DnsClientX;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestSOAAnalysis {
        [Fact]
        public async Task ParseSoaRecord() {
            var soaRecord = "ns1.example.com. hostmaster.example.com. 2023102301 3600 600 1209600 300";
            var healthCheck = new DomainHealthCheck();
            await healthCheck.CheckSOA(soaRecord);

            Assert.True(healthCheck.SOAAnalysis.RecordExists);
            Assert.Equal("ns1.example.com", healthCheck.SOAAnalysis.PrimaryNameServer);
            Assert.Equal("hostmaster.example.com", healthCheck.SOAAnalysis.ResponsibleMailbox);
            Assert.Equal(2023102301, healthCheck.SOAAnalysis.SerialNumber);
            Assert.Equal(3600, healthCheck.SOAAnalysis.Refresh);
            Assert.Equal(600, healthCheck.SOAAnalysis.Retry);
            Assert.Equal(1209600, healthCheck.SOAAnalysis.Expire);
            Assert.True(healthCheck.SOAAnalysis.SerialFormatValid);
        }

        [SkippableFact]
        public async Task VerifySoaByDomain() {
            var healthCheck = new DomainHealthCheck { Verbose = false };
            await healthCheck.Verify("evotec.pl", [HealthCheckType.SOA]);

            Skip.If(!healthCheck.SOAAnalysis.RecordExists, "SOA record not found");

            Assert.True(healthCheck.SOAAnalysis.SerialNumber > 0);
        }

        [Fact]
        public async Task InvalidSerialProvidesSuggestion() {
            var soaRecord = "ns1.example.com. hostmaster.example.com. 2023 3600 600 1209600 300";
            var healthCheck = new DomainHealthCheck();
            await healthCheck.CheckSOA(soaRecord);

            Assert.True(healthCheck.SOAAnalysis.RecordExists);
            Assert.False(healthCheck.SOAAnalysis.SerialFormatValid);
            Assert.False(string.IsNullOrEmpty(healthCheck.SOAAnalysis.SerialFormatSuggestion));
        }

        [Fact]
        public async Task NegativeCacheTtlUsesMinimum() {
            var analysis = new SOAAnalysis();
            var records = new[] {
                new DnsAnswer {
                    DataRaw = "ns1.example.com. hostmaster.example.com. 2023102301 3600 600 1209600 300",
                    Type = DnsRecordType.SOA,
                    TTL = 7200
                }
            };
            await analysis.AnalyzeSoaRecords(records, new InternalLogger());

            Assert.Equal(300, analysis.NegativeCacheTtl);
        }

        [Fact]
        public async Task NegativeCacheTtlUsesSoaTtlWhenLower() {
            var analysis = new SOAAnalysis();
            var records = new[] {
                new DnsAnswer {
                    DataRaw = "ns1.example.com. hostmaster.example.com. 2023102301 3600 600 1209600 7200",
                    Type = DnsRecordType.SOA,
                    TTL = 600
                }
            };
            await analysis.AnalyzeSoaRecords(records, new InternalLogger());

            Assert.Equal(600, analysis.NegativeCacheTtl);
        }
    }
}
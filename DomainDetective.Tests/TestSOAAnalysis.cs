using Xunit.Sdk;
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
        }

        [Fact(Skip="Requires network")]
        public async Task VerifySoaByDomain() {
            var healthCheck = new DomainHealthCheck { Verbose = false };
            await healthCheck.Verify("evotec.pl", [HealthCheckType.SOA]);

            if (!healthCheck.SOAAnalysis.RecordExists) {
                throw SkipException.ForSkip("SOA record not found");
            }

            Assert.True(healthCheck.SOAAnalysis.SerialNumber > 0);
        }
    }
}
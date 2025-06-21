using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestMXAnalysis {
        [Fact]
        public async Task TestMXRecordByString() {
            var mxRecord = "10 mail.example.com";
            var healthCheck = new DomainHealthCheck();
            await healthCheck.CheckMX(mxRecord);

            Assert.True(healthCheck.MXAnalysis.MxRecordExists);
            Assert.True(healthCheck.MXAnalysis.MxRecords.Count == 1);
            Assert.True(healthCheck.MXAnalysis.MxRecords[0] == mxRecord);
        }
    }
}

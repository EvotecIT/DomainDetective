using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestBimiHealthCheck {
        [Fact]
        public async Task ParseBimiRecordViaHealthCheck() {
            var record = "v=BIMI1; l=https://upload.wikimedia.org/wikipedia/commons/a/a7/React-icon.svg";
            var healthCheck = new DomainHealthCheck();
            await healthCheck.CheckBIMI(record);

            Assert.True(healthCheck.BimiAnalysis.BimiRecordExists);
            Assert.True(healthCheck.BimiAnalysis.StartsCorrectly);
            Assert.Equal("https://upload.wikimedia.org/wikipedia/commons/a/a7/React-icon.svg", healthCheck.BimiAnalysis.Location);
            Assert.True(healthCheck.BimiAnalysis.LocationUsesHttps);
            Assert.True(healthCheck.BimiAnalysis.SvgFetched);
            Assert.True(healthCheck.BimiAnalysis.SvgValid);
        }
    }
}
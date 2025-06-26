using System.Diagnostics;
using System.Text.Json;

namespace DomainDetective.Tests {
    public class TestToJsonPerformance {
        [Fact]
        public void ToJson_MatchesJsonSerializerPerformance() {
            var healthCheck = new DomainHealthCheck();
            var options = new JsonSerializerOptions { WriteIndented = false };
            var swSerializer = Stopwatch.StartNew();
            for (int i = 0; i < 100; i++) {
                JsonSerializer.Serialize(healthCheck, options);
            }
            swSerializer.Stop();
            var baseline = swSerializer.ElapsedTicks;

            var swMethod = Stopwatch.StartNew();
            for (int i = 0; i < 100; i++) {
                healthCheck.ToJson(options);
            }
            swMethod.Stop();

            Assert.InRange(swMethod.ElapsedTicks, 0, baseline * 2);
        }
    }
}

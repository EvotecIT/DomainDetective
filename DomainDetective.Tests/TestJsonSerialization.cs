using System.Text.Json;

namespace DomainDetective.Tests {
    public class TestJsonSerialization {
        [Fact]
        public void HealthCheckSerializationConsistent() {
            var hc = new DomainHealthCheck();
            var json1 = hc.ToJson();
            var json2 = JsonSerializer.Serialize(hc, DomainHealthCheck.JsonOptions);
            Assert.Equal(json1, json2);
        }

        [Fact]
        public void SummarySerializationConsistent() {
            var hc = new DomainHealthCheck();
            var summary = hc.BuildSummary();
            var json1 = JsonSerializer.Serialize(summary, DomainHealthCheck.JsonOptions);
            var json2 = JsonSerializer.Serialize(summary, DomainHealthCheck.JsonOptions);
            Assert.Equal(json1, json2);
        }
    }
}

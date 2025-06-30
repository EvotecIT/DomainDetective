using System.Collections.Generic;

namespace DomainDetective.Tests {
    public class TestDnsTunnelingAnalysis {
        [Fact]
        public void DetectsLongSubdomain() {
            var analysis = new DnsTunnelingAnalysis();
            var logs = new[] { "2024-01-01T00:00:00Z verylongsubdomainthatexceedslimits.example.com" };
            analysis.Analyze("example.com", logs);
            Assert.NotEmpty(analysis.Alerts);
        }

        [Fact]
        public void DetectsHighRate() {
            var analysis = new DnsTunnelingAnalysis { FrequencyThreshold = 5, FrequencyInterval = System.TimeSpan.FromSeconds(1) };
            var logs = new List<string>();
            for (int i = 0; i < 6; i++) {
                logs.Add($"2024-01-01T00:00:00Z sub{i}.example.com");
            }
            analysis.Analyze("example.com", logs);
            Assert.Contains(analysis.Alerts, a => a.Reason.Contains("High"));
        }

        [Fact]
        public void SkipsNullEntries() {
            var analysis = new DnsTunnelingAnalysis();
            string?[] logs = { null, "", "  ", "2024-01-01T00:00:00Z sub.example.com" };
            analysis.Analyze("example.com", logs);
            Assert.Empty(analysis.Alerts);
        }
    }
}

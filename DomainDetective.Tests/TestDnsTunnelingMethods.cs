namespace DomainDetective.Tests {
    public class TestDnsTunnelingMethods {
        [Fact]
        public async Task NewMethodAnalyzesLogs() {
            var hc = new DomainHealthCheck { DnsTunnelingLogs = new[] { "2024-01-01T00:00:00Z suspicious.example.com" } };
            await hc.CheckDnsTunnelingLogsAsync("example.com");
            Assert.NotEmpty(hc.DnsTunnelingAnalysis.Alerts);
        }

        [Fact]
        public async Task ObsoleteMethodStillWorks() {
#pragma warning disable CS0618
            var hc = new DomainHealthCheck { DnsTunnelingLogs = new[] { "2024-01-01T00:00:00Z suspicious.example.com" } };
            await hc.CheckDnsTunnelingAsync("example.com");
#pragma warning restore CS0618
            Assert.NotEmpty(hc.DnsTunnelingAnalysis.Alerts);
        }
    }
}

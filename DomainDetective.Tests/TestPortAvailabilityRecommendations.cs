using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using DomainDetective.Recommendations;
using Xunit;

namespace DomainDetective.Tests
{
    public class TestPortAvailabilityRecommendations
    {
        [Fact]
        public void RegistersSuccessCode()
        {
            var map = new Dictionary<string, RecommendationAdvice>();
            new PortAvailabilityRecommendations().Register(map);
            Assert.Contains(PortAvailabilityCodes.HttpResponding, map.Keys);
        }

        [Fact]
        public async Task EmitsPositiveAdvice()
        {
            using var listener = new DisposableTcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            PortAvailabilityAnalysis.ExpectedPorts[port] = (PortAvailabilityCodes.HttpResponding, "HTTP");
            var acceptTask = listener.AcceptTcpClientAsync();
            try
            {
                var analysis = new PortAvailabilityAnalysis();
                var logger = new InternalLogger();
                await analysis.AnalyzeServer("127.0.0.1", port, logger);
                var positives = RecommendationEngine.FromPositives(analysis.Assessments);
                Assert.Contains(positives, p => p.Code == PortAvailabilityCodes.HttpResponding);
                using var c = await acceptTask;
            }
            finally
            {
                listener.Stop();
                PortAvailabilityAnalysis.ExpectedPorts.TryRemove(port, out _);
            }
        }
    }
}

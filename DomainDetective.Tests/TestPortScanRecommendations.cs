using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using DomainDetective.Recommendations;
using Xunit;

namespace DomainDetective.Tests
{
    [Collection("PortScan")]
    public class TestPortScanRecommendations
    {
        [Fact]
        public void RegistersPositiveCode()
        {
            var map = new Dictionary<string, RecommendationAdvice>();
            new PortScanRecommendations().Register(map);
            Assert.Contains(PortScanCodes.ExpectedPortsOnly, map.Keys);
        }

        [Fact]
        public async Task EmitsPositiveAdvice()
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            try
            {
                var port = ((IPEndPoint)listener.LocalEndpoint).Port;
                var analysis = new PortScanAnalysis();
                var logger = new InternalLogger();
                await analysis.Scan("127.0.0.1", new[] { port }, logger);
                var positives = RecommendationEngine.FromPositives(analysis.Assessments);
                Assert.Contains(positives, p => p.Code == PortScanCodes.ExpectedPortsOnly);
            }
            finally
            {
                listener.Stop();
            }
        }
    }
}

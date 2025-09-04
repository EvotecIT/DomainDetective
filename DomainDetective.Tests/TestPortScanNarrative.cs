using DomainDetective.Narratives;
using Xunit;

namespace DomainDetective.Tests
{
    public class TestPortScanNarrative
    {
        [Fact]
        public void NarrativeSummarizesPorts()
        {
            var analysis = new PortScanAnalysis { Subject = "host" };
            analysis.Results[22] = new PortScanAnalysis.ScanResult { TcpOpen = true, Banner = "SSH" };
            analysis.Results[80] = new PortScanAnalysis.ScanResult { TcpOpen = false };
            var sections = PortScanNarrative.Build(analysis);
            Assert.Contains("Port 22 TCP open - SSH", sections.Highlights);
            Assert.Contains("Port 80 closed", sections.Details);
        }
    }
}

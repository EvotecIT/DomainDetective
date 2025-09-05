using System;
using DomainDetective.Narratives;
using Xunit;

namespace DomainDetective.Tests
{
    public class TestPortAvailabilityNarrative
    {
        [Fact]
        public void NarrativeSummarizesPorts()
        {
            var analysis = new PortAvailabilityAnalysis();
            analysis.ServerResults["host:25"] = new PortAvailabilityAnalysis.PortResult { Success = true, Latency = TimeSpan.FromMilliseconds(5) };
            analysis.ServerResults["host:80"] = new PortAvailabilityAnalysis.PortResult { Success = false, Latency = TimeSpan.FromMilliseconds(5) };
            var sections = PortAvailabilityNarrative.Build(analysis);
            Assert.Contains("host:25 reachable", sections.Highlights);
            Assert.Contains("host:80 unreachable", sections.Details);
        }
    }
}

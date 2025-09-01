using DomainDetective;
using DomainDetective.Views;
using Xunit;

namespace DomainDetective.Tests;

public class TestEdnsSupportView
{
    [Fact]
    public void SummaryReflectsCounts()
    {
        var analysis = new EdnsSupportAnalysis();
        analysis.ServerSupport["ns1 (192.0.2.1)"] = new EdnsSupportInfo { Supported = true, UdpPayloadSize = 1232, DoBit = true, TruncatedUdp = false };
        analysis.ServerSupport["ns2 (192.0.2.2)"] = new EdnsSupportInfo { Supported = true, UdpPayloadSize = 1400, DoBit = true, TruncatedUdp = true };
        analysis.ServerSupport["ns3 (192.0.2.3)"] = new EdnsSupportInfo { Supported = false, UdpPayloadSize = 0, DoBit = false, TruncatedUdp = false };

        var view = Converters.Convert(analysis);
        Assert.Equal(3, view.TotalChecked);
        Assert.Equal(2, view.SupportedCount);
        Assert.Equal(1, view.NotSupportedCount);
        Assert.Contains(">1232: 1", view.Summary);
        Assert.Contains("TCP fb: 1", view.Summary);
        Assert.Contains("no-edns: 1", view.Summary);
    }
}

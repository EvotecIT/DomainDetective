using DomainDetective;
using Xunit;

namespace DomainDetective.Tests;

[Collection("PortScan")]
public class TestPortScanProfileDefinition
{
    [Fact]
    public void ReturnsPortsForProfile()
    {
        var smb = PortScanProfileDefinition.GetPorts(PortScanProfileDefinition.PortScanProfile.SMB);
        Assert.Contains(445, smb);
        Assert.Contains(139, smb);
    }

    [Fact]
    public void AllowsOverridingPorts()
    {
        PortScanProfileDefinition.OverrideProfilePorts(PortScanProfileDefinition.PortScanProfile.NTP, new[] { 9999 });
        var ntp = PortScanProfileDefinition.GetPorts(PortScanProfileDefinition.PortScanProfile.NTP);
        Assert.Contains(9999, ntp);
        PortScanProfileDefinition.OverrideProfilePorts(PortScanProfileDefinition.PortScanProfile.NTP, new[] { 123 });
    }

    [Fact]
    public void IncludesRadiusPorts()
    {
        var ports = PortScanProfileDefinition.GetPorts(PortScanProfileDefinition.PortScanProfile.RADIUS);
        Assert.Contains(1812, ports);
        Assert.Contains(1813, ports);
    }
}

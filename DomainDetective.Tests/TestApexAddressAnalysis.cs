using DnsClientX;
using Xunit;

namespace DomainDetective.Tests;

public class TestApexAddressAnalysis {
    [Fact]
    public async Task Apex_NoAddresses() {
        var hc = new DomainDetective.DomainHealthCheck();
        hc.DnsConfiguration.QueryDnsOverride = (name, type) => Task.FromResult(Array.Empty<DnsAnswer>());

        await hc.VerifyApexAddresses("example.com");
        Assert.False(hc.ApexAddressAnalysis.HasAnyAddress);
        Assert.False(hc.ApexAddressAnalysis.HasARecord);
        Assert.False(hc.ApexAddressAnalysis.HasAaaaRecord);
        Assert.NotEmpty(hc.ApexAddressAnalysis.RfcReferences);
    }

    [Fact]
    public async Task Apex_HasAOnly() {
        var hc = new DomainDetective.DomainHealthCheck();
        hc.DnsConfiguration.QueryDnsOverride = (name, type) => {
            if (type == DnsRecordType.A && name == "example.com") {
                return Task.FromResult(new[] { new DnsAnswer { DataRaw = "203.0.113.5", Type = DnsRecordType.A } });
            }
            return Task.FromResult(Array.Empty<DnsAnswer>());
        };

        await hc.VerifyApexAddresses("example.com");
        Assert.True(hc.ApexAddressAnalysis.HasAnyAddress);
        Assert.True(hc.ApexAddressAnalysis.HasARecord);
        Assert.False(hc.ApexAddressAnalysis.HasAaaaRecord);
        Assert.Contains("203.0.113.5", hc.ApexAddressAnalysis.ARecords);
    }
}


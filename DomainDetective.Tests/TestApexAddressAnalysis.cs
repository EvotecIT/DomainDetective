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
        Assert.Equal(0, hc.ApexAddressAnalysis.IPv4Count);
        Assert.Equal(0, hc.ApexAddressAnalysis.IPv6Count);
        Assert.Equal(0, hc.ApexAddressAnalysis.DistinctSubnetCountV4);
        Assert.Equal(0, hc.ApexAddressAnalysis.DistinctSubnetCountV6);
    }

    [Fact]
    public async Task Apex_HasAOnly() {
        var hc = new DomainDetective.DomainHealthCheck();
        hc.DnsConfiguration.QueryDnsOverride = (name, type) => {
            if (type == DnsRecordType.A && name == "example.com") {
                return Task.FromResult(new[] { new DnsAnswer { DataRaw = "203.0.113.5", Type = DnsRecordType.A } });
            }
            if (type == DnsRecordType.PTR && name == "5.113.0.203.in-addr.arpa") {
                return Task.FromResult(new[] { new DnsAnswer { DataRaw = "apex.example.com.", Type = DnsRecordType.PTR } });
            }
            if (type == DnsRecordType.A && name == "apex.example.com") {
                return Task.FromResult(new[] { new DnsAnswer { DataRaw = "203.0.113.5", Type = DnsRecordType.A } });
            }
            return Task.FromResult(Array.Empty<DnsAnswer>());
        };

        await hc.VerifyApexAddresses("example.com");
        Assert.True(hc.ApexAddressAnalysis.HasAnyAddress);
        Assert.True(hc.ApexAddressAnalysis.HasARecord);
        Assert.False(hc.ApexAddressAnalysis.HasAaaaRecord);
        Assert.Contains("203.0.113.5", hc.ApexAddressAnalysis.ARecords);
        Assert.True(hc.ApexAddressAnalysis.AnyPtrPresent);
        Assert.True(hc.ApexAddressAnalysis.AllPtrPresent);
        Assert.True(hc.ApexAddressAnalysis.AllFcrDnsValid);
    }

    [Fact]
    public async Task Apex_PrivateAndDocAddressCounts() {
        var hc = new DomainDetective.DomainHealthCheck();
        hc.DnsConfiguration.QueryDnsOverride = (name, type) => {
            if (name == "example.org" && type == DnsRecordType.A) {
                return Task.FromResult(new[] {
                    new DnsAnswer { DataRaw = "10.0.0.1", Type = DnsRecordType.A },
                    new DnsAnswer { DataRaw = "192.0.2.123", Type = DnsRecordType.A }
                });
            }
            return Task.FromResult(Array.Empty<DnsAnswer>());
        };

        await hc.VerifyApexAddresses("example.org");
        Assert.Equal(2, hc.ApexAddressAnalysis.IPv4Count);
        Assert.Equal(1, hc.ApexAddressAnalysis.PrivateAddressCount);
        Assert.Equal(1, hc.ApexAddressAnalysis.DocumentationAddressCount);
        Assert.Equal(0, hc.ApexAddressAnalysis.IPv6Count);
        Assert.True(hc.ApexAddressAnalysis.PublicAddressCount >= 0);
    }
}

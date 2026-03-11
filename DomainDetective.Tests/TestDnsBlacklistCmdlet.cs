using System.Collections.Generic;
using System.Reflection;
using DomainDetective.PowerShell;
using DomainDetective.Views;

namespace DomainDetective.Tests;

public sealed class TestDnsBlacklistCmdlet
{
    [Fact]
    public void BuildViewOutput_PreservesOriginalCheckedCountWhenFilteringBlacklistedOnly()
    {
        var view = new DnsblInfo
        {
            HostsChecked = 2,
            HostsListed = 1,
            Summary = "listed hosts 1/2",
            HostSummaries = new List<DnsblHostSummary>
            {
                new DnsblHostSummary
                {
                    Key = "example.com",
                    Listed = 1,
                    Total = 1,
                    Blacklists = new[] { "listed.example" }
                },
                new DnsblHostSummary
                {
                    Key = "mail.example.com",
                    Listed = 0,
                    Total = 1,
                    Blacklists = System.Array.Empty<string>()
                }
            }
        };

        var filtered = (DnsblInfo)typeof(CmdletTestDnsBlacklist)
            .GetMethod("FilterBlacklistedOnlyView", BindingFlags.Static | BindingFlags.NonPublic)!
            .Invoke(null, new object[] { view })!;

        Assert.Equal(2, filtered.HostsChecked);
        Assert.Equal(1, filtered.HostsListed);
        Assert.Single(filtered.HostSummaries);
        Assert.Equal("listed hosts 1/2", filtered.Summary);
    }
}

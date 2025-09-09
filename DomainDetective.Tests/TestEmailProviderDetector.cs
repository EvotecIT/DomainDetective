using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective.Providers.Email;

namespace DomainDetective.Tests;

public class TestEmailProviderDetector
{
    [Fact]
    public void Detects_M365_From_SPF_And_Gateway_Mimecast_From_MX()
    {
        var mx = new [] { "10 us-smtp-inbound-1.mimecast.com" };
        var spf = new [] { "v=spf1 include:spf.protection.outlook.com -all" };
        var match = EmailProviderDetector.Detect(mxHosts: mx.Select(x => x), spfTokens: spf, dkimTargets: Array.Empty<string>());

        Assert.NotNull(match);
        Assert.NotNull(match.Primary);
        Assert.Equal("Microsoft 365", match.Primary!.DisplayName);
        Assert.Contains(match.Gateways, g => g.DisplayName.Contains("Mimecast", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Detects_SendGrid_From_SPFInclude()
    {
        var match = EmailProviderDetector.Detect(mxHosts: Array.Empty<string>(), spfTokens: new [] { "v=spf1 include:sendgrid.net -all" }, dkimTargets: Array.Empty<string>());
        Assert.NotNull(match);
        Assert.Contains(match.OutboundSenders, o => o.DisplayName.Contains("SendGrid", StringComparison.OrdinalIgnoreCase));
    }
}

using Bunit;
using DomainDetective.Toolbox.Components.Tools.Overview;
using DomainDetective.Views;

namespace DomainDetective.Website.Tests;

/// <summary>
/// The browser edition cannot request the website, registration data or subdomain sources, so it hands the overview
/// empty evidence objects and marks those sections unavailable. The page must say they were not checked rather than
/// reading the empty objects as an offline site, a missing security.txt or zero subdomains.
/// </summary>
public sealed class DomainOverviewUnavailableSectionTests : BunitContext {
    public DomainOverviewUnavailableSectionTests() {
        JSInterop.Mode = JSRuntimeMode.Loose;
    }

    [Fact]
    public void BrowserEditionOverviewSaysWebAndExposureWereNotChecked() {
        var cut = RenderOverview(BrowserEditionInfo());
        var text = cut.Markup;

        Assert.DoesNotContain("Offline", text);
        Assert.DoesNotContain("HTTP not reachable", text);
        Assert.DoesNotContain("HTTP offline", text);
        Assert.DoesNotContain("Security.txt missing", text);
        Assert.DoesNotContain("Security.txt: missing", text);
        Assert.DoesNotContain("No security.txt", text);
        Assert.DoesNotContain("0 subdomain", text);
        Assert.DoesNotContain("Expiry unknown", text);

        Assert.Contains("HTTP: not checked", text);
        Assert.Contains("Security.txt: not checked", text);
        Assert.Contains("Registration: not checked", text);
        Assert.Contains("Subdomains: not checked", text);
    }

    [Fact]
    public void FullRunStillReportsAnUnreachableSiteAsOffline() {
        var info = BrowserEditionInfo();
        info.IsBrowserLimited = false;
        info.UnavailableSections = Array.Empty<string>();

        var cut = RenderOverview(info);

        Assert.Contains("Offline", cut.Markup);
        Assert.Contains("HTTP not reachable", cut.Markup);
        Assert.Contains("Security.txt missing", cut.Markup);
        Assert.DoesNotContain("not checked", cut.Markup);
    }

    private IRenderedComponent<DomainOverviewTool> RenderOverview(DomainOverviewInfo info) {
        return Render<DomainOverviewTool>(parameters => parameters
            .Add(component => component.Info, info)
            .Add(component => component.Domain, "contoso.com"));
    }

    private static DomainOverviewInfo BrowserEditionInfo() {
        return new DomainOverviewInfo {
            Subject = "contoso.com",
            HttpReachable = false,
            SecurityTxtPublished = false,
            SubdomainCount = 0,
            Http = new HttpInfo(),
            Certificate = new CertificateInfo(),
            SecurityTxt = new SecurityTxtInfo(),
            Rdap = new RdapInfo(),
            Dnsbl = new DnsblInfo { ProvidersChecked = 12, HostsChecked = 1 },
            Subdomains = new SubdomainsInfo(),
            IsBrowserLimited = true,
            UnavailableSections = new[] { "Web and registration", "Exposure" }
        };
    }
}

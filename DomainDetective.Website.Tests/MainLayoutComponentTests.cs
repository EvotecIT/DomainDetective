using Microsoft.JSInterop;

namespace DomainDetective.Website.Tests;

public sealed class MainLayoutComponentTests : TestContext {
    public MainLayoutComponentTests() {
        JSInterop.SetupVoid("domainDetectiveTools.initTheme");
        JSInterop.SetupVoid("domainDetectiveTools.toggleTheme");
    }

    [Fact]
    public void LayoutPreservesSelectedDomainAcrossToolsNavigationLinks() {
        var navigation = Services.GetRequiredService<NavigationManager>();
        navigation.NavigateTo("http://localhost/tools/?q=contoso.com");
        RenderFragment body = builder => builder.AddMarkupContent(0, "<p>Body</p>");

        var cut = RenderComponent<DomainDetective.Website.Layout.MainLayout>(parameters => parameters
            .Add(component => component.Body, body));

        var toolsLink = cut.FindAll("a").Single(anchor => anchor.TextContent.Trim() == "Tools");
        var tryOnlineLink = cut.FindAll("a").Single(anchor => anchor.TextContent.Contains("Try Online", StringComparison.Ordinal));
        var allToolsLink = cut.FindAll("a").Single(anchor => anchor.TextContent.Trim() == "All Tools");
        var dnsToolkitLink = cut.FindAll("a").Single(anchor => anchor.TextContent.Trim() == "DnsClientX Toolkit");

        Assert.Equal("/tools/?q=contoso.com", toolsLink.GetAttribute("href"));
        Assert.Equal("/tools/?q=contoso.com", tryOnlineLink.GetAttribute("href"));
        Assert.Equal("/tools/?q=contoso.com", allToolsLink.GetAttribute("href"));
        Assert.Equal("/docs/dnsclientx/", dnsToolkitLink.GetAttribute("href"));
    }

    [Fact]
    public void LayoutOpensMobileNavigationWhenToggleIsClicked() {
        RenderFragment body = builder => builder.AddMarkupContent(0, "<p>Body</p>");

        var cut = RenderComponent<DomainDetective.Website.Layout.MainLayout>(parameters => parameters
            .Add(component => component.Body, body));

        cut.Find("button.dd-nav-toggle").Click();

        var nav = cut.Find("nav.dd-nav");
        Assert.Contains("open", nav.ClassList);
    }

    [Fact]
    public void LayoutMarksApiNavigationAsActiveInsideApiSection() {
        var navigation = Services.GetRequiredService<NavigationManager>();
        navigation.NavigateTo("http://localhost/api/powershell/");
        RenderFragment body = builder => builder.AddMarkupContent(0, "<p>Body</p>");

        var cut = RenderComponent<DomainDetective.Website.Layout.MainLayout>(parameters => parameters
            .Add(component => component.Body, body));

        var apiTrigger = cut.Find("button.dd-nav-dropdown-trigger");
        Assert.Contains("dd-nav-link", apiTrigger.ClassList);
        Assert.Contains("is-active", apiTrigger.ClassList);
    }
}

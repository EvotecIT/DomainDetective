using DomainDetective.Toolbox.Components.Shared;
using DomainDetective.Toolbox.Models;

namespace DomainDetective.Website.Tests;

public sealed class ToolWorkflowGuidanceComponentTests : BunitContext {
    [Fact]
    public void CliGuidanceQuotesDomainBeforeEmbeddingInShellCommand() {
        var tool = new ToolDefinition {
            Name = "SPF Lookup",
            Slug = "spf",
            Description = "SPF check",
            Category = ToolCategory.EmailSecurity,
            Icon = "shield",
            BrowserCompatible = true,
            InputPlaceholder = "example.com"
        };

        var cut = Render<ToolWorkflowGuidance>(parameters => parameters
            .Add(component => component.Tool, tool)
            .Add(component => component.Domain, "contoso.com && echo owned"));

        var content = cut.Markup + cut.Find(".tool-workflow-panel").TextContent;

        Assert.Contains("domaindetective check 'contoso.com && echo owned' --checks SPF", content);
    }

    [Fact]
    public void DnsLookupGuidanceUsesDnsClientXSpecificExamplesAndGuideLink() {
        var tool = new ToolDefinition {
            Name = "DNS Lookup",
            Slug = "dns-lookup",
            Description = "DNS workspace",
            Category = ToolCategory.Dns,
            Icon = "search",
            BrowserCompatible = true,
            InputPlaceholder = "example.com"
        };

        var cut = Render<ToolWorkflowGuidance>(parameters => parameters
            .Add(component => component.Tool, tool)
            .Add(component => component.Domain, "contoso.com")
            .Add(component => component.DnsResolver, "Google DNS")
            .Add(component => component.DnsHost, "_dmarc")
            .Add(component => component.DnsRequestedTypes, "TXT"));

        var content = cut.Markup + cut.Find(".tool-workflow-panel").TextContent;

        Assert.Contains("Install-Module DnsClientX -Scope CurrentUser", content);
        Assert.Contains("Resolve-Dns -Name", content);
        Assert.Contains("_dmarc.contoso.com", content);
        Assert.Contains("-Type TXT", content);
        Assert.Contains("DnsProvider Google", content);
        Assert.Contains("using DnsClientX;", content);
        Assert.Contains("DnsRecordType.TXT", content);
        Assert.Contains("DnsEndpoint.Google", content);
        Assert.Contains("/docs/dnsclientx/", cut.Markup);
        Assert.Contains("/docs/dns-workspace/", cut.Markup);
        Assert.Contains("/docs/dns-examples/", cut.Markup);
    }
}

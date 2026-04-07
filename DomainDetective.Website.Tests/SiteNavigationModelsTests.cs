using System.Text.Json;
using DomainDetective.Website.Models;

namespace DomainDetective.Website.Tests;

public sealed class SiteNavigationModelsTests {
    [Fact]
    public void SiteNavigationItemDeserializesUrlIntoHref() {
        var item = JsonSerializer.Deserialize<SiteNavigationItem>("{\"title\":\"Docs\",\"url\":\"/docs/\"}");

        Assert.NotNull(item);
        Assert.Equal("/docs/", item!.Href);
        Assert.Equal("/docs/", item.Url);
    }

    [Fact]
    public void SiteNavigationActionDeserializesUrlIntoHref() {
        var action = JsonSerializer.Deserialize<SiteNavigationAction>("{\"title\":\"Try Online\",\"url\":\"/tools/\"}");

        Assert.NotNull(action);
        Assert.Equal("/tools/", action!.Href);
        Assert.Equal("/tools/", action.Url);
    }
}

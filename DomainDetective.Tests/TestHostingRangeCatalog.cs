using System.IO;
using System.Linq;
using DomainDetective.Providers.Endpoint;
using DomainDetective.Providers.Hosting;

namespace DomainDetective.Tests;

public class TestHostingRangeCatalog {
    private const string Sample =
        "# sample\n" +
        "198.51.100.0/22\tExample Cloud\tCloud\t\teu-west-1\n" +
        "198.51.100.0/24\tExample Cloud\tCloud\tCOMPUTE\teu-west-1\n" +
        "198.51.100.0/24\tExample Cloud\tCloud\tSTORAGE\teu-west-1\n" +
        "203.0.113.0/24\tExample Edge\tCdn\t\t\n" +
        "2001:db8:1000::/36\tExample Edge\tCdn\t\t\n" +
        "as64500\tExample Edge\tCdn\t\t\n";

    private static HostingRangeCatalog Catalog() => HostingRangeCatalog.Parse(new StringReader(Sample));

    [Fact]
    public void TheMostSpecificPublishedRangeWinsAndNamesEveryService() {
        HostingAttribution? match = Catalog().Match("198.51.100.20");

        Assert.NotNull(match);
        Assert.Equal("Example Cloud", match!.Provider);
        Assert.Equal("198.51.100.0/24", match.MatchedBy);
        Assert.Equal("COMPUTE, STORAGE", match.Service);
        Assert.Equal(HostingMatchKind.PublishedRange, match.MatchKind);
        Assert.Equal(EndpointAttributionConfidence.High, match.Confidence);

        Assert.Equal("198.51.100.0/22", Catalog().Match("198.51.102.1")!.MatchedBy);
    }

    [Fact]
    public void MatchesIpv6AndMappedIpv4Addresses() {
        Assert.Equal(HostingKind.Cdn, Catalog().Match("2001:db8:1fff::1")!.Kind);
        Assert.Equal("Example Edge", Catalog().Match("::ffff:203.0.113.7")!.Provider);
        Assert.Null(Catalog().Match("2001:db8:2000::1"));
    }

    [Fact]
    public void AnAutonomousSystemMatchIsUsedOnlyWithoutARangeAndIsWeaker() {
        HostingAttribution? byNetwork = Catalog().Match("192.0.2.1", 64500);
        HostingAttribution? byRange = Catalog().Match("198.51.100.20", 64500);

        Assert.Equal(HostingMatchKind.AutonomousSystem, byNetwork!.MatchKind);
        Assert.Equal("AS64500", byNetwork.MatchedBy);
        Assert.Equal(EndpointAttributionConfidence.Medium, byNetwork.Confidence);
        Assert.Equal("Example Cloud", byRange!.Provider);
        Assert.Null(Catalog().Match("192.0.2.1", 64999));
    }

    [Theory]
    [InlineData("104.16.132.229", "Cloudflare")]
    [InlineData("151.101.1.69", "Fastly")]
    [InlineData("23.1.2.3", "Akamai")]
    public void TheBundledCatalogNamesPublishedCdnRanges(string address, string provider) {
        HostingAttribution? match = HostingRangeCatalog.Default.Match(address);

        Assert.Equal(provider, match?.Provider);
        Assert.Equal(HostingKind.Cdn, match!.Kind);
    }

    [Fact]
    public void TheBundledCatalogCoversEveryPublishingProvider() {
        HostingRangeCatalog catalog = HostingRangeCatalog.Default;

        Assert.True(catalog.RangeCount > 1000);
        foreach (string provider in new[] { "Amazon Web Services", "Google Cloud", "Cloudflare", "Fastly", "Akamai" }) {
            Assert.Contains(provider, catalog.Providers);
        }
        Assert.Contains(catalog.Notes, n => n.Contains("Update-HostingRanges.ps1"));
    }
}

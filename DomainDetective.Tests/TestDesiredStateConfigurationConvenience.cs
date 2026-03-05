using DomainDetective.DesiredState;
using Xunit;

namespace DomainDetective.Tests;

public sealed class TestDesiredStateConfigurationConvenience {
    [Fact]
    public void ConvenienceGetter_DoesNotAutoInitializeDefaults() {
        var cfg = new DesiredStateConfiguration();

        Assert.Null(cfg.Defaults.Dmarc);
        _ = cfg.Dmarc;
        Assert.Null(cfg.Defaults.Dmarc);

        Assert.Null(cfg.Defaults.Spf);
        _ = cfg.Spf;
        Assert.Null(cfg.Defaults.Spf);

        Assert.Null(cfg.Defaults.CertificateInventory);
        _ = cfg.CertificateInventory;
        Assert.Null(cfg.Defaults.CertificateInventory);
    }
}

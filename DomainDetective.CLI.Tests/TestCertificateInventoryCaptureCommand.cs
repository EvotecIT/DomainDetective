using DomainDetective.CLI.Commands;

namespace DomainDetective.CLI.Tests;

[Collection("HttpListener")]
public class TestCertificateInventoryCaptureCommand {
    [Fact]
    public async Task ExecuteAsync_ReturnsErrorWhenNoDomainsProvided() {
        var command = new CertificateInventoryCaptureCommand();
        var settings = new CertificateInventoryCaptureSettings();

        var exitCode = await command.ExecuteAsync(null!, settings);

        Assert.Equal(1, exitCode);
    }

    [Fact]
    public async Task ExecuteAsync_SucceedsWithoutNetworkWhenAllDiscoveryAndProbesDisabled() {
        var command = new CertificateInventoryCaptureCommand();
        var settings = new CertificateInventoryCaptureSettings {
            Domains = new[] { "example.com" },
            NoApexHttps = true,
            NoWwwHttps = true,
            DisableMxDiscovery = true,
            DisableSmtpStartTls = true,
            DisableSubmissionStartTls = true,
            IncludeImapTls = false,
            IncludePop3Tls = false,
            NoPersist = true,
            Json = true
        };

        var exitCode = await command.ExecuteAsync(null!, settings);

        Assert.Equal(0, exitCode);
    }

    [Fact]
    public async Task ExecuteAsync_AllowsZeroReuseTtls_WhenReuseSwitchesAreDisabled() {
        var command = new CertificateInventoryCaptureCommand();
        var settings = new CertificateInventoryCaptureSettings {
            Domains = new[] { "example.com" },
            NoApexHttps = true,
            NoWwwHttps = true,
            DisableMxDiscovery = true,
            DisableSmtpStartTls = true,
            DisableSubmissionStartTls = true,
            IncludeImapTls = false,
            IncludePop3Tls = false,
            RecentResultTtlHours = 0,
            RecentFailureResultTtlHours = 0,
            NoPersist = true,
            Json = true
        };

        var exitCode = await command.ExecuteAsync(null!, settings);

        Assert.Equal(0, exitCode);
    }
}

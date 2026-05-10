using System;
using System.IO;
using DomainDetective.CLI.Commands;

namespace DomainDetective.CLI.Tests;

[Collection("HttpListener")]
public class TestCertificateInventoryCaptureCommand {
    [Fact]
    public async Task ExecuteAsync_ReturnsErrorWhenNoDomainsProvided() {
        var command = new CertificateInventoryCaptureCommand();
        var settings = new CertificateInventoryCaptureSettings();

        var exitCode = await command.ExecuteForTestingAsync(null!, settings);

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

        var exitCode = await command.ExecuteForTestingAsync(null!, settings);

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

        var exitCode = await command.ExecuteForTestingAsync(null!, settings);

        Assert.Equal(0, exitCode);
    }

    [Fact]
    public async Task ExecuteAsync_WritesCsvWithProvenanceColumns_WhenRequested() {
        string csvPath = Path.Combine(Path.GetTempPath(), "dd-ci-csv-" + Guid.NewGuid().ToString("N") + ".csv");
        string summaryCsvPath = Path.Combine(
            Path.GetDirectoryName(csvPath) ?? string.Empty,
            Path.GetFileNameWithoutExtension(csvPath) + ".target-decision-summary" + Path.GetExtension(csvPath));
        try {
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
                CsvPath = csvPath
            };

            var exitCode = await command.ExecuteForTestingAsync(null!, settings);

            Assert.Equal(0, exitCode);
            Assert.True(File.Exists(csvPath));
            Assert.True(File.Exists(summaryCsvPath));
            string header = Assert.Single(File.ReadAllLines(csvPath));
            string summaryHeader = Assert.Single(File.ReadAllLines(summaryCsvPath));
            Assert.Contains("TargetOrigins", header, StringComparison.Ordinal);
            Assert.Contains("CaptureDisposition", header, StringComparison.Ordinal);
            Assert.Contains("Severity", summaryHeader, StringComparison.Ordinal);
            Assert.Contains("RecommendedAction", summaryHeader, StringComparison.Ordinal);
            Assert.Contains("TargetOrigins", summaryHeader, StringComparison.Ordinal);
        } finally {
            if (File.Exists(csvPath)) {
                File.Delete(csvPath);
            }
            if (File.Exists(summaryCsvPath)) {
                File.Delete(summaryCsvPath);
            }
        }
    }

    [Fact]
    public async Task ExecuteAsync_WritesTargetDecisionSummaryNdjson_WhenRequested() {
        string ndjsonPath = Path.Combine(Path.GetTempPath(), "dd-ci-ndjson-" + Guid.NewGuid().ToString("N") + ".ndjson");
        string summaryNdjsonPath = Path.Combine(
            Path.GetDirectoryName(ndjsonPath) ?? string.Empty,
            Path.GetFileNameWithoutExtension(ndjsonPath) + ".target-decision-summary" + Path.GetExtension(ndjsonPath));
        try {
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
                AdditionalEndpoints = new[] { "ftp://example.com" },
                NoPersist = true,
                NdjsonPath = ndjsonPath
            };

            var exitCode = await command.ExecuteForTestingAsync(null!, settings);

            Assert.Equal(0, exitCode);
            Assert.True(File.Exists(ndjsonPath));
            Assert.True(File.Exists(summaryNdjsonPath));
            string summaryLine = Assert.Single(File.ReadAllLines(summaryNdjsonPath));
            Assert.Contains("\"RecordType\":\"TargetDecisionSummary\"", summaryLine, StringComparison.Ordinal);
            Assert.Contains("\"Severity\":\"warning\"", summaryLine, StringComparison.Ordinal);
            Assert.Contains("\"Reason\":\"unsupported-scheme\"", summaryLine, StringComparison.Ordinal);
        } finally {
            if (File.Exists(ndjsonPath)) {
                File.Delete(ndjsonPath);
            }
            if (File.Exists(summaryNdjsonPath)) {
                File.Delete(summaryNdjsonPath);
            }
        }
    }

    [Fact]
    public async Task ExecuteAsync_ReturnsStrictFailure_WhenWarningTargetDecisionsArePresent() {
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
            AdditionalEndpoints = new[] { "ftp://example.com" },
            NoPersist = true,
            FailOnWarningTargetDecisions = true,
            Json = true
        };

        var exitCode = await command.ExecuteForTestingAsync(null!, settings);

        Assert.Equal(2, exitCode);
    }
}

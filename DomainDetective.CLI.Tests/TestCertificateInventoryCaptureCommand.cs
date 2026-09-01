using System;
using System.IO;
using DomainDetective.CLI.Commands;
using Spectre.Console;

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

    [Theory]
    [InlineData(-2)]
    [InlineData(0)]
    [InlineData(301)]
    public async Task ExecuteAsync_ReturnsErrorForInvalidFtpTlsTimeout(int timeoutSeconds) {
        IAnsiConsole originalConsole = AnsiConsole.Console;
        using var output = new StringWriter();
        AnsiConsole.Console = AnsiConsole.Create(new AnsiConsoleSettings {
            Ansi = AnsiSupport.No,
            ColorSystem = ColorSystemSupport.NoColors,
            Out = new AnsiConsoleOutput(output)
        });
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
                FtpTlsTimeoutSeconds = timeoutSeconds
            };

            int exitCode = await command.ExecuteForTestingAsync(null!, settings);

            Assert.Equal(1, exitCode);
            Assert.Contains(
                "--ftps-timeout-seconds must be between 1 and 300.",
                output.ToString(),
                StringComparison.Ordinal);
        } finally {
            AnsiConsole.Console = originalConsole;
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(513)]
    public async Task ExecuteAsync_ReturnsErrorForInvalidDnsEnrichmentParallelism(int parallelism) {
        IAnsiConsole originalConsole = AnsiConsole.Console;
        using var output = new StringWriter();
        AnsiConsole.Console = AnsiConsole.Create(new AnsiConsoleSettings {
            Ansi = AnsiSupport.No,
            ColorSystem = ColorSystemSupport.NoColors,
            Out = new AnsiConsoleOutput(output)
        });
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
                DnsEnrichmentParallelism = parallelism
            };

            int exitCode = await command.ExecuteForTestingAsync(null!, settings);

            Assert.Equal(1, exitCode);
            Assert.Contains(
                "--dns-enrichment-parallelism must be between 1 and 512.",
                output.ToString(),
                StringComparison.Ordinal);
        } finally {
            AnsiConsole.Console = originalConsole;
        }
    }

    [Fact]
    public async Task ExecuteAsync_AllowsEndpointOnlyCapture() {
        var command = new CertificateInventoryCaptureCommand();
        var settings = new CertificateInventoryCaptureSettings {
            AdditionalEndpoints = new[] { "ftp://localhost" },
            NoApexHttps = true,
            NoWwwHttps = true,
            DisableMxDiscovery = true,
            NoPersist = true,
            Json = true
        };

        int exitCode = await command.ExecuteForTestingAsync(null!, settings);

        Assert.Equal(0, exitCode);
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
            Assert.Contains("DnsObservedAtUtc", header, StringComparison.Ordinal);
            Assert.Contains("AttributionCandidates", header, StringComparison.Ordinal);
            Assert.Contains("AttributionEvaluatedAtUtc", header, StringComparison.Ordinal);
            Assert.Contains("AzureServiceTagChangeNumber", header, StringComparison.Ordinal);
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
    public void WriteCsv_RetainsAllAttributionCandidatesAndCatalogProvenance() {
        string csvPath = Path.Combine(Path.GetTempPath(), "dd-attribution-csv-" + Guid.NewGuid().ToString("N") + ".csv");
        try {
            var evidence = new DomainDetective.Providers.Endpoint.EndpointAttributionEvidence {
                Kind = DomainDetective.Providers.Endpoint.EndpointAttributionSignalKind.CertificateIssuer,
                ObservedValue = "Example Issuer",
                MatchedValue = "Example",
                Score = 0.15,
                Source = "test-source"
            };
            var candidate = new DomainDetective.Providers.Endpoint.EndpointAttributionCandidate {
                ProviderId = "review-provider",
                ServiceId = "review-service",
                DisplayName = "Review Candidate",
                Score = 0.15,
                Confidence = DomainDetective.Providers.Endpoint.EndpointAttributionConfidence.Low,
                EligibleAsPrimary = false,
                RuleId = "test.review-candidate",
                RuleVersion = "1",
                Evidence = new[] { evidence }
            };
            var entry = new CertificateInventoryEntry {
                Host = "service.example.com",
                ResolvedHost = "service.example.com",
                Port = 443,
                Service = "HTTPS",
                Attribution = new DomainDetective.Providers.Endpoint.EndpointAttributionResult {
                    Candidates = new[] { candidate },
                    EvaluatedAtUtc = DateTimeOffset.UtcNow,
                    AzureServiceTagSource = "service-tags.json",
                    AzureServiceTagChangeNumber = "42",
                    AzureServiceTagCloud = "Public",
                    AzureServiceTagRetrievedAtUtc = DateTimeOffset.UtcNow.AddMinutes(-5)
                }
            };
            var result = new CertificateInventoryCaptureResult {
                CapturedAtUtc = DateTimeOffset.UtcNow,
                Snapshot = new CertificateInventorySnapshot { Entries = new List<CertificateInventoryEntry> { entry } }
            };

            CertificateInventoryCaptureCommand.WriteCsv(result, csvPath);

            string csv = File.ReadAllText(csvPath);
            Assert.Contains("review-provider", csv, StringComparison.Ordinal);
            Assert.Contains("test.review-candidate", csv, StringComparison.Ordinal);
            Assert.Contains("CertificateIssuer", csv, StringComparison.Ordinal);
            Assert.Contains("service-tags.json", csv, StringComparison.Ordinal);
            Assert.Contains("42", csv, StringComparison.Ordinal);
        } finally {
            if (File.Exists(csvPath)) {
                File.Delete(csvPath);
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

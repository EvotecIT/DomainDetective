using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

public class TestCertificateInventoryCapture {
    [Fact]
    public async Task CaptureAsync_DiscoversEndpointsAndPersistsSnapshot_WithOverrides() {
        using var certificate = CreateSelfSignedWithEku(CertificateExtendedKeyUsageAnalyzer.ServerAuthenticationOid);
        CertificateInventorySnapshot? persistedSnapshot = null;
        string? persistedCacheDirectory = null;
        var capture = new CertificateInventoryCapture {
            MxLookupOverride = (domain, dnsConfiguration, maxMxHostsPerDomain, cancellationToken) => {
                IReadOnlyList<string> hosts = domain.Equals("example.com", StringComparison.OrdinalIgnoreCase)
                    ? new[] { "mx1.example.com", "mx2.example.com", "mx2.example.com" }
                    : new[] { "mail.contoso.com" };
                return Task.FromResult(hosts);
            },
            HttpsProbeOverride = (httpsTargets, options, logger, cancellationToken) => {
                var entries = new List<CertificateMonitor.Entry>();
                foreach (var target in httpsTargets) {
                    entries.Add(CreateHttpsEntry(target, certificate));
                }
                return Task.FromResult<IReadOnlyList<CertificateMonitor.Entry>>(entries);
            },
            PersistSnapshotOverride = (snapshot, cacheDirectory, logger) => {
                persistedSnapshot = snapshot;
                persistedCacheDirectory = cacheDirectory;
                return "mock://snapshot.json";
            }
        };

        var options = new CertificateInventoryCaptureOptions {
            CacheDirectory = @"C:\temp\cert-monitor",
            IncludeApexHttps = true,
            IncludeWwwHttps = true,
            IncludeMxHosts = true,
            IncludeMxHttps = true,
            IncludeSmtpStartTls = false,
            IncludeSubmissionStartTls = false,
            IncludeImapTls = false,
            IncludePop3Tls = false,
            PersistSnapshot = true
        };
        options.AdditionalEndpoints.Add("https://api.example.com:8443");
        options.AdditionalEndpoints.Add("ftp://unsupported.example.com");

        var result = await capture.CaptureAsync(new[] {
            "example.com",
            "https://example.com",
            "contoso.com",
            "not a domain"
        }, options, cancellationToken: CancellationToken.None);

        Assert.Equal(2, result.DomainCount);
        Assert.Equal(3, result.MxHostCount);
        Assert.Equal(8, result.HttpsEndpointCount);
        Assert.Equal(0, result.MailEndpointCount);
        Assert.Equal(8, result.EntryCount);
        Assert.Equal(8, result.UniqueEndpointCount);
        Assert.Equal(8, result.ValidCount);
        Assert.Equal(0, result.ExpiredCount);
        Assert.Equal(0, result.FailedCount);
        Assert.Equal("mock://snapshot.json", result.SnapshotPath);
        Assert.NotNull(persistedSnapshot);
        Assert.Equal(options.CacheDirectory, persistedCacheDirectory);
        Assert.Contains(result.Warnings, warning => warning.Contains("Skipping invalid domain", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(result.Warnings, warning => warning.Contains("unsupported endpoint scheme", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task CaptureAsync_DeduplicatesEntriesByEndpointAndKeepsMostUsefulRecord() {
        using var certificate = CreateSelfSignedWithEku(CertificateExtendedKeyUsageAnalyzer.ServerAuthenticationOid);
        var capture = new CertificateInventoryCapture {
            HttpsProbeOverride = (httpsTargets, options, logger, cancellationToken) => {
                var validEntry = CreateHttpsEntry("https://dup.example.com", certificate);
                var failedEntry = new CertificateMonitor.Entry {
                    Host = "dup.example.com",
                    Url = "https://dup.example.com/",
                    ResolvedHost = "dup.example.com",
                    Scheme = "https",
                    Port = 443,
                    Service = "HTTPS",
                    Valid = false,
                    Expired = false,
                    ChainComplete = false,
                    Protocol = SslProtocols.None,
                    Analysis = new CertificateAnalysis {
                        Url = "https://dup.example.com/",
                        IsReachable = false
                    }
                };

                IReadOnlyList<CertificateMonitor.Entry> entries = new[] { failedEntry, validEntry };
                return Task.FromResult(entries);
            }
        };

        var options = new CertificateInventoryCaptureOptions {
            IncludeApexHttps = false,
            IncludeWwwHttps = false,
            IncludeMxHosts = false,
            IncludeMxHttps = false,
            IncludeSmtpStartTls = false,
            IncludeSubmissionStartTls = false,
            IncludeImapTls = false,
            IncludePop3Tls = false,
            PersistSnapshot = false
        };
        options.AdditionalEndpoints.Add("https://dup.example.com");

        var result = await capture.CaptureAsync(new[] { "example.com" }, options, cancellationToken: CancellationToken.None);

        Assert.Equal(1, result.HttpsEndpointCount);
        Assert.Equal(1, result.EntryCount);
        Assert.Equal(1, result.ValidCount);
        Assert.Equal(0, result.FailedCount);
        Assert.Single(result.Snapshot.Entries);
        Assert.False(string.IsNullOrWhiteSpace(result.Snapshot.Entries[0].CertificateThumbprint));
    }

    [Fact]
    public async Task CaptureAsync_DoesNotDiscoverMx_WhenIncludeMxHostsIsDisabled() {
        var mxLookupCalled = false;
        var capture = new CertificateInventoryCapture {
            MxLookupOverride = (domain, dnsConfiguration, maxMxHostsPerDomain, cancellationToken) => {
                mxLookupCalled = true;
                IReadOnlyList<string> hosts = new[] { "mx1.example.com" };
                return Task.FromResult(hosts);
            }
        };

        var options = new CertificateInventoryCaptureOptions {
            IncludeApexHttps = false,
            IncludeWwwHttps = false,
            IncludeMxHosts = false,
            IncludeMxHttps = false,
            IncludeSmtpStartTls = true,
            IncludeSubmissionStartTls = true,
            IncludeImapTls = true,
            IncludePop3Tls = true,
            PersistSnapshot = false
        };

        var result = await capture.CaptureAsync(new[] { "example.com" }, options, cancellationToken: CancellationToken.None);

        Assert.False(mxLookupCalled);
        Assert.Equal(0, result.MxHostCount);
        Assert.Equal(0, result.MailEndpointCount);
        Assert.Equal(0, result.EntryCount);
    }

    [Fact]
    public async Task CaptureAsync_IncludesCtDiscoveredSubdomains_WhenEnabled() {
        using var certificate = CreateSelfSignedWithEku(CertificateExtendedKeyUsageAnalyzer.ServerAuthenticationOid);
        var capture = new CertificateInventoryCapture {
            CtSubdomainDiscoveryOverride = (domains, options, logger, cancellationToken) => {
                IReadOnlyList<string> discovered = new[] { "portal.example.com", "api.example.com", "portal.example.com" };
                return Task.FromResult(discovered);
            },
            HttpsProbeOverride = (httpsTargets, options, logger, cancellationToken) => {
                var entries = new List<CertificateMonitor.Entry>();
                foreach (var target in httpsTargets) {
                    entries.Add(CreateHttpsEntry(target, certificate));
                }
                return Task.FromResult<IReadOnlyList<CertificateMonitor.Entry>>(entries);
            }
        };

        var options = new CertificateInventoryCaptureOptions {
            IncludeApexHttps = false,
            IncludeWwwHttps = false,
            IncludeCtDiscoveredSubdomains = true,
            VerifyCtDiscoveredSubdomains = false,
            IncludeMxHosts = false,
            IncludeMxHttps = false,
            IncludeSmtpStartTls = false,
            IncludeSubmissionStartTls = false,
            IncludeImapTls = false,
            IncludePop3Tls = false,
            PersistSnapshot = false
        };

        var result = await capture.CaptureAsync(new[] { "example.com" }, options, cancellationToken: CancellationToken.None);

        Assert.Equal(2, result.CtDiscoveredSubdomainCount);
        Assert.Equal(2, result.HttpsEndpointCount);
        Assert.Equal(2, result.EntryCount);
        Assert.Contains(result.Snapshot.Entries, entry => entry.Host.Equals("portal.example.com", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(result.Snapshot.Entries, entry => entry.Host.Equals("api.example.com", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task CaptureAsync_AppliesMaxTargetsLimit_WhenConfigured() {
        using var certificate = CreateSelfSignedWithEku(CertificateExtendedKeyUsageAnalyzer.ServerAuthenticationOid);
        var capture = new CertificateInventoryCapture {
            HttpsProbeOverride = (httpsTargets, options, logger, cancellationToken) => {
                var entries = new List<CertificateMonitor.Entry>();
                foreach (var target in httpsTargets) {
                    entries.Add(CreateHttpsEntry(target, certificate));
                }
                return Task.FromResult<IReadOnlyList<CertificateMonitor.Entry>>(entries);
            }
        };

        var options = new CertificateInventoryCaptureOptions {
            IncludeApexHttps = true,
            IncludeWwwHttps = true,
            IncludeMxHosts = false,
            IncludeMxHttps = false,
            IncludeSmtpStartTls = false,
            IncludeSubmissionStartTls = false,
            IncludeImapTls = false,
            IncludePop3Tls = false,
            MaxTargets = 2,
            PersistSnapshot = false
        };
        options.AdditionalEndpoints.Add("https://api.example.com:8443");
        options.AdditionalEndpoints.Add("https://portal.example.com:9443");

        var result = await capture.CaptureAsync(new[] { "example.com" }, options, cancellationToken: CancellationToken.None);

        Assert.Equal(2, result.HttpsEndpointCount);
        Assert.Equal(0, result.MailEndpointCount);
        Assert.Equal(2, result.EntryCount);
        Assert.Contains(result.Warnings, warning => warning.Contains("capped", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task CaptureAsync_ReusesRecentSnapshotEntries_WhenEnabled() {
        var cacheDirectory = Path.Combine(Path.GetTempPath(), "dd-ci-cache-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(cacheDirectory);
        try {
            var snapshot = new CertificateInventorySnapshot {
                CapturedAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10),
                Port = 443
            };
            snapshot.Entries.Add(new CertificateInventoryEntry {
                Host = "api.example.com",
                ResolvedHost = "api.example.com",
                Url = "https://api.example.com/",
                Scheme = "https",
                Port = 443,
                Service = "HTTPS",
                CertificateThumbprint = "ABC123",
                IsReachable = true,
                Valid = true,
                Expired = false,
                NotAfterUtc = DateTimeOffset.UtcNow.AddDays(120)
            });

            using (var monitor = new CertificateMonitor {
                CacheDirectory = cacheDirectory,
                PersistInventorySnapshots = false
            }) {
                monitor.SaveInventorySnapshot(snapshot);
            }

            var observedHttpsTargets = -1;
            var capture = new CertificateInventoryCapture {
                HttpsProbeOverride = (httpsTargets, options, logger, cancellationToken) => {
                    observedHttpsTargets = httpsTargets.Count;
                    return Task.FromResult<IReadOnlyList<CertificateMonitor.Entry>>(Array.Empty<CertificateMonitor.Entry>());
                }
            };

            var options = new CertificateInventoryCaptureOptions {
                CacheDirectory = cacheDirectory,
                IncludeApexHttps = false,
                IncludeWwwHttps = false,
                IncludeMxHosts = false,
                IncludeMxHttps = false,
                IncludeSmtpStartTls = false,
                IncludeSubmissionStartTls = false,
                IncludeImapTls = false,
                IncludePop3Tls = false,
                ReuseRecentSnapshotEntries = true,
                RecentSnapshotTtl = TimeSpan.FromHours(24),
                ReprobeExpiringWithinDays = 14,
                PersistSnapshot = false
            };
            options.AdditionalEndpoints.Add("https://api.example.com");

            var result = await capture.CaptureAsync(new[] { "example.com" }, options, cancellationToken: CancellationToken.None);

            Assert.Equal(0, observedHttpsTargets);
            Assert.Equal(1, result.EntryCount);
            Assert.Equal(1, result.ValidCount);
            Assert.Contains(result.Snapshot.Entries, entry => entry.Host.Equals("api.example.com", StringComparison.OrdinalIgnoreCase));
        } finally {
            try {
                Directory.Delete(cacheDirectory, true);
            } catch {
                // no-op
            }
        }
    }

    [Fact]
    public void TryExtractMxHost_RejectsNullMxAndNumericArtifacts() {
        Assert.True(CertificateInventoryCapture.TryExtractMxHost("10 mail.example.com.", out var hostFromPriority));
        Assert.Equal("mail.example.com", hostFromPriority);

        Assert.True(CertificateInventoryCapture.TryExtractMxHost("mail.example.com.", out var hostWithoutPriority));
        Assert.Equal("mail.example.com", hostWithoutPriority);

        Assert.False(CertificateInventoryCapture.TryExtractMxHost("0 .", out _));
        Assert.False(CertificateInventoryCapture.TryExtractMxHost("0", out _));
        Assert.False(CertificateInventoryCapture.TryExtractMxHost(".", out _));
    }

    [Fact]
    public async Task CaptureAsync_FiltersInvalidMxHosts_WhenLookupOverrideReturnsArtifacts() {
        using var certificate = CreateSelfSignedWithEku(CertificateExtendedKeyUsageAnalyzer.ServerAuthenticationOid);
        var capture = new CertificateInventoryCapture {
            MxLookupOverride = (domain, dnsConfiguration, maxMxHostsPerDomain, cancellationToken) => {
                IReadOnlyList<string> hosts = new[] {
                    "0",
                    ".",
                    "-",
                    "192.168.1.10",
                    " mx1.example.com. ",
                    "mx2.example.com"
                };
                return Task.FromResult(hosts);
            },
            HttpsProbeOverride = (httpsTargets, options, logger, cancellationToken) => {
                var entries = new List<CertificateMonitor.Entry>();
                foreach (var target in httpsTargets) {
                    entries.Add(CreateHttpsEntry(target, certificate));
                }
                return Task.FromResult<IReadOnlyList<CertificateMonitor.Entry>>(entries);
            }
        };

        var options = new CertificateInventoryCaptureOptions {
            IncludeApexHttps = false,
            IncludeWwwHttps = false,
            IncludeMxHosts = true,
            IncludeMxHttps = true,
            IncludeSmtpStartTls = false,
            IncludeSubmissionStartTls = false,
            IncludeImapTls = false,
            IncludePop3Tls = false,
            PersistSnapshot = false
        };

        var result = await capture.CaptureAsync(new[] { "example.com" }, options, cancellationToken: CancellationToken.None);

        Assert.Equal(2, result.MxHostCount);
        Assert.Equal(2, result.HttpsEndpointCount);
        Assert.DoesNotContain(result.MxHosts, host => host.Equals("0", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(result.MxHosts, host => host.Equals("mx1.example.com", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(result.MxHosts, host => host.Equals("mx2.example.com", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ConfigureHttpsAnalysis_DisabledProfileTurnsOffCtSources() {
        var analysis = new CertificateAnalysis();
        var options = new CertificateInventoryCaptureOptions {
            CtProfile = CertificateCtEnrichmentProfile.Disabled,
            EnableCensysCtSource = true,
            EnableShodanCtSource = true,
            CensysApiId = "id",
            CensysApiSecret = "secret",
            ShodanApiKey = "key"
        };

        CertificateInventoryCapture.ConfigureHttpsAnalysis(analysis, options);

        Assert.Empty(analysis.CtLogApiTemplates);
        Assert.False(analysis.EnableCensysCtSource);
        Assert.False(analysis.EnableShodanCtSource);
        Assert.Null(analysis.CensysApiId);
        Assert.Null(analysis.CensysApiSecret);
        Assert.Null(analysis.ShodanApiKey);
    }

    [Fact]
    public void ConfigureHttpsAnalysis_ExtendedProfileAutoEnablesCommercialSources_WhenCredentialsProvided() {
        var analysis = new CertificateAnalysis();
        var options = new CertificateInventoryCaptureOptions {
            CtProfile = CertificateCtEnrichmentProfile.Extended,
            IncludeDefaultCtTemplate = true,
            CensysApiId = "id",
            CensysApiSecret = "secret",
            CensysCtApiUrlTemplate = "https://search.censys.io/api/v1/view/certificates/{0}",
            ShodanApiKey = "key"
        };
        options.CtApiTemplates.Add("https://crt.sh/?identity=%25.{0}&output=json");

        CertificateInventoryCapture.ConfigureHttpsAnalysis(analysis, options);

        Assert.True(analysis.EnableCensysCtSource);
        Assert.True(analysis.EnableShodanCtSource);
        Assert.Contains("https://crt.sh/?sha256={0}&output=json", analysis.CtLogApiTemplates);
        Assert.Contains("https://crt.sh/?identity=%25.{0}&output=json", analysis.CtLogApiTemplates);
    }

    private static CertificateMonitor.Entry CreateHttpsEntry(string url, X509Certificate2 certificate) {
        var uri = new Uri(url);
        var analysis = new CertificateAnalysis {
            Url = url,
            Certificate = certificate,
            IsReachable = true
        };
        analysis.Chain.Add(certificate);
        return new CertificateMonitor.Entry {
            Host = uri.Host,
            Url = url,
            ResolvedHost = uri.Host,
            Scheme = uri.Scheme,
            Port = uri.Port,
            Service = uri.Port == 443 ? "HTTPS" : "HTTPS-Alt",
            ExpiryDate = certificate.NotAfter,
            Valid = true,
            Expired = false,
            ChainComplete = true,
            Protocol = SslProtocols.Tls12,
            Analysis = analysis
        };
    }

    private static X509Certificate2 CreateSelfSignedWithEku(string oidValue) {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=capture.test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var oids = new OidCollection {
            new Oid(oidValue)
        };
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(oids, false));
        var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        return new X509Certificate2(certificate.Export(X509ContentType.Cert));
    }
}

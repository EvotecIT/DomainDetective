using System;
using System.Collections.Generic;
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

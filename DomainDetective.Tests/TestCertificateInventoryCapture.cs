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
    public async Task CaptureAsync_ExplicitHostSeedProbesRequestedHostWithoutWwwOrMxExpansion() {
        using var certificate = CreateSelfSignedWithEku(CertificateExtendedKeyUsageAnalyzer.ServerAuthenticationOid);
        var mxLookupCalls = 0;
        List<string>? observedTargets = null;
        var capture = new CertificateInventoryCapture {
            MxLookupOverride = (domain, dnsConfiguration, maxMxHostsPerDomain, cancellationToken) => {
                mxLookupCalls++;
                return Task.FromResult<IReadOnlyList<string>>(new[] { "mx1.example.com" });
            },
            HttpsProbeOverride = (httpsTargets, options, logger, cancellationToken) => {
                observedTargets = httpsTargets.ToList();
                var entries = new List<CertificateMonitor.Entry>();
                foreach (var target in httpsTargets) {
                    entries.Add(CreateHttpsEntry(target, certificate));
                }

                return Task.FromResult<IReadOnlyList<CertificateMonitor.Entry>>(entries);
            }
        };

        var options = new CertificateInventoryCaptureOptions {
            IncludeApexHttps = false,
            IncludeWwwHttps = true,
            IncludeMxHosts = true,
            IncludeMxHttps = true,
            IncludeSmtpStartTls = false,
            IncludeSubmissionStartTls = false,
            IncludeImapTls = false,
            IncludePop3Tls = false,
            PersistSnapshot = false
        };

        var result = await capture.CaptureAsync(new[] { "portal.example.com" }, options, cancellationToken: CancellationToken.None);

        Assert.NotNull(observedTargets);
        Assert.Single(observedTargets!);
        Assert.Equal("https://portal.example.com/", observedTargets[0]);
        Assert.DoesNotContain(observedTargets, target => target.Contains("www.portal.example.com", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(0, mxLookupCalls);
        Assert.Equal(1, result.HttpsEndpointCount);
        Assert.Equal(0, result.MxHostCount);
        Assert.Equal("portal.example.com", Assert.Single(result.Domains));
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
            EnablePassiveCtFallback = true,
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
    public async Task CaptureAsync_PrioritizesExpiringTargets_WhenApplyingMaxTargetsLimit() {
        var cacheDirectory = Path.Combine(Path.GetTempPath(), "dd-ci-priority-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(cacheDirectory);
        try {
            var snapshot = new CertificateInventorySnapshot {
                CapturedAtUtc = DateTimeOffset.UtcNow.AddMinutes(-5),
                Port = 443
            };
            snapshot.Entries.Add(new CertificateInventoryEntry {
                Host = "portal.example.com",
                ResolvedHost = "portal.example.com",
                Url = "https://portal.example.com/",
                Scheme = "https",
                Port = 443,
                Service = "HTTPS",
                CertificateThumbprint = "EXPIRING123",
                IsReachable = true,
                Valid = true,
                Expired = false,
                NotAfterUtc = DateTimeOffset.UtcNow.AddDays(3)
            });
            snapshot.Entries.Add(new CertificateInventoryEntry {
                Host = "api.example.com",
                ResolvedHost = "api.example.com",
                Url = "https://api.example.com/",
                Scheme = "https",
                Port = 443,
                Service = "HTTPS",
                CertificateThumbprint = "HEALTHY123",
                IsReachable = true,
                Valid = true,
                Expired = false,
                NotAfterUtc = DateTimeOffset.UtcNow.AddDays(180)
            });

            using (var monitor = new CertificateMonitor {
                CacheDirectory = cacheDirectory,
                PersistInventorySnapshots = false
            }) {
                monitor.SaveInventorySnapshot(snapshot);
            }

            using var certificate = CreateSelfSignedWithEku(CertificateExtendedKeyUsageAnalyzer.ServerAuthenticationOid);
            var observedHttpsTargets = new List<string>();
            var capture = new CertificateInventoryCapture {
                HttpsProbeOverride = (httpsTargets, options, logger, cancellationToken) => {
                    observedHttpsTargets.AddRange(httpsTargets);
                    var entries = new List<CertificateMonitor.Entry>();
                    foreach (var target in httpsTargets) {
                        entries.Add(CreateHttpsEntry(target, certificate));
                    }

                    return Task.FromResult<IReadOnlyList<CertificateMonitor.Entry>>(entries);
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
                MaxTargets = 1,
                PersistSnapshot = false
            };
            options.AdditionalEndpoints.Add("https://portal.example.com");
            options.AdditionalEndpoints.Add("https://api.example.com");

            var result = await capture.CaptureAsync(new[] { "example.com" }, options, cancellationToken: CancellationToken.None);

            Assert.Single(observedHttpsTargets);
            Assert.Contains(observedHttpsTargets, target => target.Contains("portal.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.DoesNotContain(observedHttpsTargets, target => target.Contains("api.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Equal(1, result.HttpsEndpointCount);
            Assert.Equal(1, result.EntryCount);
        } finally {
            try {
                Directory.Delete(cacheDirectory, true);
            } catch {
                // no-op
            }
        }
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
            EnablePassiveCtFallback = true,
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

    [Fact]
    public void ConfigureHttpsAnalysis_DoesNotIncludeDefaultPassiveTemplate_WhenPassiveFallbackDisabled() {
        var analysis = new CertificateAnalysis();
        var options = new CertificateInventoryCaptureOptions {
            CtProfile = CertificateCtEnrichmentProfile.Default,
            EnablePassiveCtFallback = false,
            IncludeDefaultCtTemplate = true
        };

        CertificateInventoryCapture.ConfigureHttpsAnalysis(analysis, options);

        Assert.DoesNotContain("https://crt.sh/?sha256={0}&output=json", analysis.CtLogApiTemplates);
    }

    [Fact]
    public void ConfigureHttpsAnalysis_AppliesConfiguredHttpsTimeout() {
        var analysis = new CertificateAnalysis();
        var options = new CertificateInventoryCaptureOptions {
            HttpsTimeout = TimeSpan.FromSeconds(7)
        };

        CertificateInventoryCapture.ConfigureHttpsAnalysis(analysis, options);

        Assert.Equal(TimeSpan.FromSeconds(7), analysis.Timeout);
    }

    [Fact]
    public async Task CaptureAsync_HydratesUnreachableCtEndpointWithCtCertificateMetadata() {
        var ctFirstSeen = new DateTimeOffset(2024, 1, 5, 10, 0, 0, TimeSpan.Zero);
        var ctLastSeen = new DateTimeOffset(2026, 2, 10, 12, 0, 0, TimeSpan.Zero);
        var ctNotBefore = new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var ctNotAfter = new DateTimeOffset(2026, 10, 1, 23, 59, 59, TimeSpan.Zero);
        var capture = new CertificateInventoryCapture {
            CtSubdomainEntryDiscoveryOverride = (domains, options, logger, cancellationToken) => {
                IReadOnlyList<SubdomainDiscoveryEntry> discovered = new[] {
                    new SubdomainDiscoveryEntry {
                        Name = "ct-only.example.com",
                        FirstSeenUtc = ctFirstSeen,
                        LastSeenUtc = ctLastSeen,
                        LatestCertificateCtEntryTimestampUtc = ctLastSeen,
                        LatestCertificateSubject = "CN=ct-only.example.com",
                        LatestCertificateIssuer = "CN=Test Issuer, O=Example",
                        LatestCertificateSerialNumber = "ABC123",
                        LatestCertificateNotBeforeUtc = ctNotBefore,
                        LatestCertificateNotAfterUtc = ctNotAfter,
                        CtSources = new[] { "crt.sh", "certspotter" },
                        CertificateObservationCount = 4,
                        ResolutionStatus = SubdomainResolutionStatus.Unknown
                    }
                };
                return Task.FromResult(discovered);
            },
            HttpsProbeOverride = (httpsTargets, options, logger, cancellationToken) => {
                var entries = new List<CertificateMonitor.Entry>();
                foreach (var target in httpsTargets) {
                    var uri = new Uri(target);
                    entries.Add(new CertificateMonitor.Entry {
                        Host = uri.Host,
                        ResolvedHost = uri.Host,
                        Url = target,
                        Scheme = uri.Scheme,
                        Port = uri.Port,
                        Service = "HTTPS",
                        Valid = false,
                        Expired = false,
                        ChainComplete = false,
                        Protocol = SslProtocols.None,
                        Analysis = new CertificateAnalysis {
                            Url = target,
                            IsReachable = false
                        }
                    });
                }
                return Task.FromResult<IReadOnlyList<CertificateMonitor.Entry>>(entries);
            }
        };

        var options = new CertificateInventoryCaptureOptions {
            IncludeApexHttps = false,
            IncludeWwwHttps = false,
            IncludeCtDiscoveredSubdomains = true,
            VerifyCtDiscoveredSubdomains = false,
            EnablePassiveCtFallback = true,
            IncludeMxHosts = false,
            IncludeMxHttps = false,
            IncludeSmtpStartTls = false,
            IncludeSubmissionStartTls = false,
            IncludeImapTls = false,
            IncludePop3Tls = false,
            PersistSnapshot = false
        };

        var result = await capture.CaptureAsync(new[] { "example.com" }, options, cancellationToken: CancellationToken.None);

        var endpoint = Assert.Single(result.Snapshot.Entries);
        Assert.Equal("ct-only.example.com", endpoint.Host);
        Assert.False(endpoint.IsReachable);
        Assert.True(endpoint.PresentInCtLogs);
        Assert.Equal("CN=ct-only.example.com", endpoint.CertificateSubject);
        Assert.Equal("CN=Test Issuer, O=Example", endpoint.CertificateIssuer);
        Assert.Equal("ABC123", endpoint.CertificateSerialNumber);
        Assert.Equal(ctNotBefore, endpoint.NotBeforeUtc);
        Assert.Equal(ctNotAfter, endpoint.NotAfterUtc);
        Assert.Equal(ctFirstSeen, endpoint.CtFirstSeenUtc);
        Assert.Equal(ctLastSeen, endpoint.CtLastSeenUtc);
        Assert.Equal(ctLastSeen, endpoint.CtLatestCertificateEntryTimestampUtc);
        Assert.Equal("ct-log", endpoint.CertificateChainSource);
        Assert.Contains("ct-log", endpoint.CertificateChainSources, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("crt.sh", endpoint.CtDiscoverySources, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("certspotter", endpoint.CtDiscoverySources, StringComparer.OrdinalIgnoreCase);

        var discovered = Assert.Single(result.CtDiscoveredSubdomainEntries);
        Assert.Equal("ct-only.example.com", discovered.Name);
        Assert.Equal(ctLastSeen, discovered.LatestCertificateCtEntryTimestampUtc);
        Assert.Equal("CN=ct-only.example.com", discovered.LatestCertificateSubject);
    }

    [Fact]
    public async Task CaptureAsync_HydratesUnreachableCtEndpointWithNativeCtMetadata_WhenPassiveFallbackDisabled() {
        var ctFirstSeen = new DateTimeOffset(2025, 2, 1, 9, 0, 0, TimeSpan.Zero);
        var ctLastSeen = new DateTimeOffset(2026, 3, 5, 15, 42, 37, TimeSpan.Zero);
        var ctNotBefore = new DateTimeOffset(2025, 2, 1, 0, 0, 0, TimeSpan.Zero);
        var ctNotAfter = new DateTimeOffset(2026, 5, 1, 23, 59, 59, TimeSpan.Zero);
        var capture = new CertificateInventoryCapture {
            CtSubdomainEntryDiscoveryOverride = (domains, options, logger, cancellationToken) => {
                IReadOnlyList<SubdomainDiscoveryEntry> discovered = new[] {
                    new SubdomainDiscoveryEntry {
                        Name = "native-only.example.com",
                        FirstSeenUtc = ctFirstSeen,
                        LastSeenUtc = ctLastSeen,
                        LatestCertificateCtEntryTimestampUtc = ctLastSeen,
                        LatestCertificateSubject = "CN=native-only.example.com",
                        LatestCertificateIssuer = "CN=Native CT Issuer, O=Example",
                        LatestCertificateSerialNumber = "NATIVE123",
                        LatestCertificateNotBeforeUtc = ctNotBefore,
                        LatestCertificateNotAfterUtc = ctNotAfter,
                        CtSources = new[] { "native-ct" },
                        CertificateObservationCount = 3,
                        ResolutionStatus = SubdomainResolutionStatus.Unknown
                    }
                };
                return Task.FromResult(discovered);
            },
            CtPassiveMetadataBackfillOverride = (domains, options, logger, cancellationToken) => {
                throw new InvalidOperationException("Passive CT fallback should remain disabled for native-only metadata hydration.");
            },
            HttpsProbeOverride = (httpsTargets, options, logger, cancellationToken) => {
                var entries = new List<CertificateMonitor.Entry>();
                foreach (var target in httpsTargets) {
                    var uri = new Uri(target);
                    entries.Add(new CertificateMonitor.Entry {
                        Host = uri.Host,
                        ResolvedHost = uri.Host,
                        Url = target,
                        Scheme = uri.Scheme,
                        Port = uri.Port,
                        Service = "HTTPS",
                        Valid = false,
                        Expired = false,
                        ChainComplete = false,
                        Protocol = SslProtocols.None,
                        Analysis = new CertificateAnalysis {
                            Url = target,
                            IsReachable = false
                        }
                    });
                }
                return Task.FromResult<IReadOnlyList<CertificateMonitor.Entry>>(entries);
            }
        };

        var options = new CertificateInventoryCaptureOptions {
            IncludeApexHttps = false,
            IncludeWwwHttps = false,
            IncludeCtDiscoveredSubdomains = true,
            VerifyCtDiscoveredSubdomains = false,
            EnablePassiveCtFallback = false,
            IncludeMxHosts = false,
            IncludeMxHttps = false,
            IncludeSmtpStartTls = false,
            IncludeSubmissionStartTls = false,
            IncludeImapTls = false,
            IncludePop3Tls = false,
            BackfillMissingCtCertificateMetadata = true,
            PersistSnapshot = false
        };

        var result = await capture.CaptureAsync(new[] { "example.com" }, options, cancellationToken: CancellationToken.None);

        var endpoint = Assert.Single(result.Snapshot.Entries);
        Assert.Equal("native-only.example.com", endpoint.Host);
        Assert.False(endpoint.IsReachable);
        Assert.True(endpoint.PresentInCtLogs);
        Assert.Equal("CN=native-only.example.com", endpoint.CertificateSubject);
        Assert.Equal("CN=Native CT Issuer, O=Example", endpoint.CertificateIssuer);
        Assert.Equal("NATIVE123", endpoint.CertificateSerialNumber);
        Assert.Equal(ctNotBefore, endpoint.NotBeforeUtc);
        Assert.Equal(ctNotAfter, endpoint.NotAfterUtc);
        Assert.Equal(ctFirstSeen, endpoint.CtFirstSeenUtc);
        Assert.Equal(ctLastSeen, endpoint.CtLastSeenUtc);
        Assert.Equal(ctLastSeen, endpoint.CtLatestCertificateEntryTimestampUtc);
        Assert.Equal("ct-log", endpoint.CertificateChainSource);
        Assert.Contains("ct-log", endpoint.CertificateChainSources, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("native-ct", endpoint.CtDiscoverySources, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("crt.sh", endpoint.CtDiscoverySources, StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task CaptureAsync_BackfillsMissingCtCertificateMetadataFromPassiveSource() {
        var ctFirstSeen = new DateTimeOffset(2025, 12, 1, 10, 0, 0, TimeSpan.Zero);
        var ctLastSeen = new DateTimeOffset(2026, 3, 5, 15, 42, 37, TimeSpan.Zero);
        var ctEntryTimestamp = new DateTimeOffset(2026, 2, 20, 9, 30, 0, TimeSpan.Zero);
        var notBefore = new DateTimeOffset(2025, 5, 12, 0, 0, 0, TimeSpan.Zero);
        var notAfter = new DateTimeOffset(2026, 6, 10, 23, 59, 59, TimeSpan.Zero);

        var capture = new CertificateInventoryCapture {
            CtSubdomainEntryDiscoveryOverride = (domains, options, logger, cancellationToken) => {
                IReadOnlyList<SubdomainDiscoveryEntry> discovered = new[] {
                    new SubdomainDiscoveryEntry {
                        Name = "airtoxics.eurofins.com",
                        FirstSeenUtc = ctFirstSeen,
                        LastSeenUtc = ctLastSeen,
                        CtSources = new[] { "native-ct" },
                        CertificateObservationCount = 2,
                        ResolutionStatus = SubdomainResolutionStatus.Resolves
                    }
                };
                return Task.FromResult(discovered);
            },
            CtPassiveMetadataBackfillOverride = (domains, options, logger, cancellationToken) => {
                IReadOnlyList<SubdomainDiscoveryEntry> discovered = new[] {
                    new SubdomainDiscoveryEntry {
                        Name = "airtoxics.eurofins.com",
                        FirstSeenUtc = ctFirstSeen,
                        LastSeenUtc = ctLastSeen,
                        LatestCertificateCtEntryTimestampUtc = ctEntryTimestamp,
                        LatestCertificateSubject = "CN=airtoxics.eurofins.com",
                        LatestCertificateIssuer = "CN=Amazon RSA 2048 M03, O=Amazon, C=US",
                        LatestCertificateSerialNumber = "0C43361CBC44B340CDC357EEBB806963",
                        LatestCertificateNotBeforeUtc = notBefore,
                        LatestCertificateNotAfterUtc = notAfter,
                        CtSources = new[] { "crt.sh" },
                        CertificateObservationCount = 1,
                        ResolutionStatus = SubdomainResolutionStatus.Resolves
                    }
                };
                return Task.FromResult(discovered);
            },
            HttpsProbeOverride = (httpsTargets, options, logger, cancellationToken) => {
                var entries = new List<CertificateMonitor.Entry>();
                foreach (var target in httpsTargets) {
                    var uri = new Uri(target);
                    entries.Add(new CertificateMonitor.Entry {
                        Host = uri.Host,
                        ResolvedHost = uri.Host,
                        Url = target,
                        Scheme = uri.Scheme,
                        Port = uri.Port,
                        Service = "HTTPS",
                        Valid = false,
                        Expired = false,
                        ChainComplete = false,
                        Protocol = SslProtocols.None,
                        Analysis = new CertificateAnalysis {
                            Url = target,
                            IsReachable = false
                        }
                    });
                }
                return Task.FromResult<IReadOnlyList<CertificateMonitor.Entry>>(entries);
            }
        };

        var options = new CertificateInventoryCaptureOptions {
            IncludeApexHttps = false,
            IncludeWwwHttps = false,
            IncludeCtDiscoveredSubdomains = true,
            VerifyCtDiscoveredSubdomains = false,
            EnablePassiveCtFallback = true,
            IncludeMxHosts = false,
            IncludeMxHttps = false,
            IncludeSmtpStartTls = false,
            IncludeSubmissionStartTls = false,
            IncludeImapTls = false,
            IncludePop3Tls = false,
            BackfillMissingCtCertificateMetadata = true,
            PersistSnapshot = false
        };

        var result = await capture.CaptureAsync(new[] { "eurofins.com" }, options, cancellationToken: CancellationToken.None);
        var endpoint = Assert.Single(result.Snapshot.Entries);
        Assert.Equal("airtoxics.eurofins.com", endpoint.Host);
        Assert.False(endpoint.IsReachable);
        Assert.True(endpoint.PresentInCtLogs);
        Assert.Equal("CN=airtoxics.eurofins.com", endpoint.CertificateSubject);
        Assert.Equal("CN=Amazon RSA 2048 M03, O=Amazon, C=US", endpoint.CertificateIssuer);
        Assert.Equal("0C43361CBC44B340CDC357EEBB806963", endpoint.CertificateSerialNumber);
        Assert.Equal(notBefore, endpoint.NotBeforeUtc);
        Assert.Equal(notAfter, endpoint.NotAfterUtc);
        Assert.Equal(ctEntryTimestamp, endpoint.CtLatestCertificateEntryTimestampUtc);
        Assert.Contains("native-ct", endpoint.CtDiscoverySources, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("crt.sh", endpoint.CtDiscoverySources, StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task CaptureAsync_BackfillsCtCertificateMetadataWhenPassiveMetadataFallbackEnabledWithoutPassiveDiscoveryFallback() {
        var nativeCtFirstSeen = new DateTimeOffset(2026, 3, 5, 10, 21, 27, TimeSpan.Zero);
        var nativeCtLastSeen = new DateTimeOffset(2026, 3, 5, 15, 42, 37, TimeSpan.Zero);
        var passiveCtEntryTimestamp = new DateTimeOffset(2022, 7, 11, 15, 36, 47, TimeSpan.Zero);
        var notBefore = new DateTimeOffset(2022, 7, 11, 0, 0, 0, TimeSpan.Zero);
        var notAfter = new DateTimeOffset(2023, 8, 11, 23, 59, 59, TimeSpan.Zero);

        var capture = new CertificateInventoryCapture {
            CtSubdomainEntryDiscoveryOverride = (domains, options, logger, cancellationToken) => {
                IReadOnlyList<SubdomainDiscoveryEntry> discovered = new[] {
                    new SubdomainDiscoveryEntry {
                        Name = "airtoxics.eurofins.com",
                        FirstSeenUtc = nativeCtFirstSeen,
                        LastSeenUtc = nativeCtLastSeen,
                        CtSources = new[] { "native-ct" },
                        CertificateObservationCount = 2,
                        ResolutionStatus = SubdomainResolutionStatus.Resolves
                    }
                };
                return Task.FromResult(discovered);
            },
            CtPassiveMetadataBackfillOverride = (domains, options, logger, cancellationToken) => {
                string target = Assert.Single(domains);
                IReadOnlyList<SubdomainDiscoveryEntry> discovered = string.Equals(target, "airtoxics.eurofins.com", StringComparison.OrdinalIgnoreCase)
                    ? new[] {
                        new SubdomainDiscoveryEntry {
                            Name = "airtoxics.eurofins.com",
                            FirstSeenUtc = passiveCtEntryTimestamp,
                            LastSeenUtc = passiveCtEntryTimestamp,
                            LatestCertificateCtEntryTimestampUtc = passiveCtEntryTimestamp,
                            LatestCertificateSubject = "CN=airtoxics.eurofins.com",
                            LatestCertificateIssuer = "CN=Sectigo RSA Domain Validation Secure Server CA, O=Sectigo Limited, C=GB",
                            LatestCertificateSerialNumber = "0CE4A3C00C1DD4890B9EBA4223FE917F",
                            LatestCertificateNotBeforeUtc = notBefore,
                            LatestCertificateNotAfterUtc = notAfter,
                            CtSources = new[] { "crt.sh" },
                            CertificateObservationCount = 1,
                            ResolutionStatus = SubdomainResolutionStatus.Resolves
                        }
                    }
                    : Array.Empty<SubdomainDiscoveryEntry>();
                return Task.FromResult(discovered);
            },
            HttpsProbeOverride = (httpsTargets, options, logger, cancellationToken) => {
                var entries = new List<CertificateMonitor.Entry>();
                foreach (var target in httpsTargets) {
                    var uri = new Uri(target);
                    entries.Add(new CertificateMonitor.Entry {
                        Host = uri.Host,
                        ResolvedHost = uri.Host,
                        Url = target,
                        Scheme = uri.Scheme,
                        Port = uri.Port,
                        Service = "HTTPS",
                        Valid = false,
                        Expired = false,
                        ChainComplete = false,
                        Protocol = SslProtocols.None,
                        Analysis = new CertificateAnalysis {
                            Url = target,
                            IsReachable = false
                        }
                    });
                }
                return Task.FromResult<IReadOnlyList<CertificateMonitor.Entry>>(entries);
            }
        };

        var options = new CertificateInventoryCaptureOptions {
            IncludeApexHttps = false,
            IncludeWwwHttps = false,
            IncludeCtDiscoveredSubdomains = true,
            VerifyCtDiscoveredSubdomains = false,
            EnablePassiveCtFallback = false,
            EnablePassiveCtMetadataFallback = true,
            IncludeMxHosts = false,
            IncludeMxHttps = false,
            IncludeSmtpStartTls = false,
            IncludeSubmissionStartTls = false,
            IncludeImapTls = false,
            IncludePop3Tls = false,
            BackfillMissingCtCertificateMetadata = true,
            PersistSnapshot = false
        };

        var result = await capture.CaptureAsync(new[] { "eurofins.com" }, options, cancellationToken: CancellationToken.None);
        var endpoint = Assert.Single(result.Snapshot.Entries);
        Assert.Equal("airtoxics.eurofins.com", endpoint.Host);
        Assert.False(endpoint.IsReachable);
        Assert.True(endpoint.PresentInCtLogs);
        Assert.Equal("CN=airtoxics.eurofins.com", endpoint.CertificateSubject);
        Assert.Equal("CN=Sectigo RSA Domain Validation Secure Server CA, O=Sectigo Limited, C=GB", endpoint.CertificateIssuer);
        Assert.Equal("0CE4A3C00C1DD4890B9EBA4223FE917F", endpoint.CertificateSerialNumber);
        Assert.Equal(notBefore, endpoint.NotBeforeUtc);
        Assert.Equal(notAfter, endpoint.NotAfterUtc);
        Assert.Equal(passiveCtEntryTimestamp, endpoint.CtLatestCertificateEntryTimestampUtc);
        Assert.Contains("native-ct", endpoint.CtDiscoverySources, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("crt.sh", endpoint.CtDiscoverySources, StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task CaptureAsync_BackfillsMissingCtCertificateMetadataFromExactPassiveHostWhenDomainBackfillMissesHost() {
        var nativeCtFirstSeen = new DateTimeOffset(2026, 3, 5, 10, 21, 27, TimeSpan.Zero);
        var nativeCtLastSeen = new DateTimeOffset(2026, 3, 5, 15, 42, 37, TimeSpan.Zero);
        var passiveCtFirstSeen = new DateTimeOffset(2020, 7, 15, 19, 26, 46, TimeSpan.Zero);
        var passiveCtLastSeen = new DateTimeOffset(2022, 7, 11, 15, 36, 47, TimeSpan.Zero);
        var ctEntryTimestamp = passiveCtLastSeen;
        var notBefore = new DateTimeOffset(2022, 7, 11, 0, 0, 0, TimeSpan.Zero);
        var notAfter = new DateTimeOffset(2023, 8, 11, 23, 59, 59, TimeSpan.Zero);

        var capture = new CertificateInventoryCapture {
            CtSubdomainEntryDiscoveryOverride = (domains, options, logger, cancellationToken) => {
                IReadOnlyList<SubdomainDiscoveryEntry> discovered = new[] {
                    new SubdomainDiscoveryEntry {
                        Name = "airtoxics.eurofins.com",
                        FirstSeenUtc = nativeCtFirstSeen,
                        LastSeenUtc = nativeCtLastSeen,
                        CtSources = new[] { "native-ct" },
                        CertificateObservationCount = 2,
                        ResolutionStatus = SubdomainResolutionStatus.Resolves
                    }
                };
                return Task.FromResult(discovered);
            },
            CtPassiveMetadataBackfillOverride = (domains, options, logger, cancellationToken) => {
                string target = Assert.Single(domains);
                IReadOnlyList<SubdomainDiscoveryEntry> discovered = string.Equals(target, "airtoxics.eurofins.com", StringComparison.OrdinalIgnoreCase)
                    ? new[] {
                        new SubdomainDiscoveryEntry {
                            Name = "airtoxics.eurofins.com",
                            FirstSeenUtc = passiveCtFirstSeen,
                            LastSeenUtc = passiveCtLastSeen,
                            LatestCertificateCtEntryTimestampUtc = ctEntryTimestamp,
                            LatestCertificateSubject = "CN=airtoxics.eurofins.com",
                            LatestCertificateIssuer = "CN=Sectigo RSA Domain Validation Secure Server CA, O=Sectigo Limited, C=GB",
                            LatestCertificateSerialNumber = "0CE4A3C00C1DD4890B9EBA4223FE917F",
                            LatestCertificateNotBeforeUtc = notBefore,
                            LatestCertificateNotAfterUtc = notAfter,
                            CtSources = new[] { "crt.sh" },
                            CertificateObservationCount = 4,
                            ResolutionStatus = SubdomainResolutionStatus.Resolves
                        }
                    }
                    : Array.Empty<SubdomainDiscoveryEntry>();
                return Task.FromResult(discovered);
            },
            HttpsProbeOverride = (httpsTargets, options, logger, cancellationToken) => {
                var entries = new List<CertificateMonitor.Entry>();
                foreach (var target in httpsTargets) {
                    var uri = new Uri(target);
                    entries.Add(new CertificateMonitor.Entry {
                        Host = uri.Host,
                        ResolvedHost = uri.Host,
                        Url = target,
                        Scheme = uri.Scheme,
                        Port = uri.Port,
                        Service = "HTTPS",
                        Valid = false,
                        Expired = false,
                        ChainComplete = false,
                        Protocol = SslProtocols.None,
                        Analysis = new CertificateAnalysis {
                            Url = target,
                            IsReachable = false
                        }
                    });
                }
                return Task.FromResult<IReadOnlyList<CertificateMonitor.Entry>>(entries);
            }
        };

        var options = new CertificateInventoryCaptureOptions {
            IncludeApexHttps = false,
            IncludeWwwHttps = false,
            IncludeCtDiscoveredSubdomains = true,
            VerifyCtDiscoveredSubdomains = false,
            EnablePassiveCtFallback = true,
            IncludeMxHosts = false,
            IncludeMxHttps = false,
            IncludeSmtpStartTls = false,
            IncludeSubmissionStartTls = false,
            IncludeImapTls = false,
            IncludePop3Tls = false,
            MaxCtSubdomainsPerDomain = 1,
            BackfillMissingCtCertificateMetadata = true,
            PersistSnapshot = false
        };

        var result = await capture.CaptureAsync(new[] { "eurofins.com" }, options, cancellationToken: CancellationToken.None);
        var endpoint = Assert.Single(result.Snapshot.Entries);
        Assert.Equal("airtoxics.eurofins.com", endpoint.Host);
        Assert.False(endpoint.IsReachable);
        Assert.True(endpoint.PresentInCtLogs);
        Assert.Equal("CN=airtoxics.eurofins.com", endpoint.CertificateSubject);
        Assert.Equal("CN=Sectigo RSA Domain Validation Secure Server CA, O=Sectigo Limited, C=GB", endpoint.CertificateIssuer);
        Assert.Equal("0CE4A3C00C1DD4890B9EBA4223FE917F", endpoint.CertificateSerialNumber);
        Assert.Equal(notBefore, endpoint.NotBeforeUtc);
        Assert.Equal(notAfter, endpoint.NotAfterUtc);
        Assert.Equal(passiveCtFirstSeen, endpoint.CtFirstSeenUtc);
        Assert.Equal(nativeCtLastSeen, endpoint.CtLastSeenUtc);
        Assert.Equal(ctEntryTimestamp, endpoint.CtLatestCertificateEntryTimestampUtc);
        Assert.Contains("native-ct", endpoint.CtDiscoverySources, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("crt.sh", endpoint.CtDiscoverySources, StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task CaptureAsync_DoesNotBackfillPassiveCtMetadataWhenPassiveFallbackDisabled() {
        var ctFirstSeen = new DateTimeOffset(2025, 12, 1, 10, 0, 0, TimeSpan.Zero);
        var ctLastSeen = new DateTimeOffset(2026, 3, 5, 15, 42, 37, TimeSpan.Zero);

        var capture = new CertificateInventoryCapture {
            CtSubdomainEntryDiscoveryOverride = (domains, options, logger, cancellationToken) => {
                IReadOnlyList<SubdomainDiscoveryEntry> discovered = new[] {
                    new SubdomainDiscoveryEntry {
                        Name = "airtoxics.eurofins.com",
                        FirstSeenUtc = ctFirstSeen,
                        LastSeenUtc = ctLastSeen,
                        CtSources = new[] { "native-ct" },
                        CertificateObservationCount = 2,
                        ResolutionStatus = SubdomainResolutionStatus.Resolves
                    }
                };
                return Task.FromResult(discovered);
            },
            CtPassiveMetadataBackfillOverride = (domains, options, logger, cancellationToken) => {
                throw new InvalidOperationException("Passive CT fallback should stay disabled.");
            },
            HttpsProbeOverride = (httpsTargets, options, logger, cancellationToken) => {
                var entries = new List<CertificateMonitor.Entry>();
                foreach (var target in httpsTargets) {
                    var uri = new Uri(target);
                    entries.Add(new CertificateMonitor.Entry {
                        Host = uri.Host,
                        ResolvedHost = uri.Host,
                        Url = target,
                        Scheme = uri.Scheme,
                        Port = uri.Port,
                        Service = "HTTPS",
                        Valid = false,
                        Expired = false,
                        ChainComplete = false,
                        Protocol = SslProtocols.None,
                        Analysis = new CertificateAnalysis {
                            Url = target,
                            IsReachable = false
                        }
                    });
                }
                return Task.FromResult<IReadOnlyList<CertificateMonitor.Entry>>(entries);
            }
        };

        var options = new CertificateInventoryCaptureOptions {
            IncludeApexHttps = false,
            IncludeWwwHttps = false,
            IncludeCtDiscoveredSubdomains = true,
            VerifyCtDiscoveredSubdomains = false,
            EnablePassiveCtFallback = false,
            IncludeMxHosts = false,
            IncludeMxHttps = false,
            IncludeSmtpStartTls = false,
            IncludeSubmissionStartTls = false,
            IncludeImapTls = false,
            IncludePop3Tls = false,
            BackfillMissingCtCertificateMetadata = true,
            PersistSnapshot = false
        };

        var result = await capture.CaptureAsync(new[] { "eurofins.com" }, options, cancellationToken: CancellationToken.None);
        var endpoint = Assert.Single(result.Snapshot.Entries);
        Assert.Equal("airtoxics.eurofins.com", endpoint.Host);
        Assert.False(endpoint.IsReachable);
        Assert.True(endpoint.PresentInCtLogs);
        Assert.Null(endpoint.CertificateSubject);
        Assert.Null(endpoint.CertificateIssuer);
        Assert.Null(endpoint.CertificateSerialNumber);
        Assert.Null(endpoint.CtLatestCertificateEntryTimestampUtc);
        Assert.DoesNotContain("crt.sh", endpoint.CtDiscoverySources, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("native-ct", endpoint.CtDiscoverySources, StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task CaptureAsync_BackfillsExactHostSeedCtMetadataWhenPassiveMetadataFallbackEnabled() {
        var ctEntryTimestamp = new DateTimeOffset(2022, 7, 11, 15, 36, 47, TimeSpan.Zero);
        var notBefore = new DateTimeOffset(2022, 7, 11, 0, 0, 0, TimeSpan.Zero);
        var notAfter = new DateTimeOffset(2023, 8, 11, 23, 59, 59, TimeSpan.Zero);

        var capture = new CertificateInventoryCapture {
            CtPassiveMetadataBackfillOverride = (domains, options, logger, cancellationToken) => {
                string target = Assert.Single(domains);
                IReadOnlyList<SubdomainDiscoveryEntry> discovered = string.Equals(target, "airtoxics.eurofins.com", StringComparison.OrdinalIgnoreCase)
                    ? new[] {
                        new SubdomainDiscoveryEntry {
                            Name = "airtoxics.eurofins.com",
                            FirstSeenUtc = ctEntryTimestamp,
                            LastSeenUtc = ctEntryTimestamp,
                            LatestCertificateCtEntryTimestampUtc = ctEntryTimestamp,
                            LatestCertificateSubject = "CN=airtoxics.eurofins.com",
                            LatestCertificateIssuer = "CN=Sectigo RSA Domain Validation Secure Server CA, O=Sectigo Limited, C=GB",
                            LatestCertificateSerialNumber = "0CE4A3C00C1DD4890B9EBA4223FE917F",
                            LatestCertificateNotBeforeUtc = notBefore,
                            LatestCertificateNotAfterUtc = notAfter,
                            CtSources = new[] { "crt.sh" },
                            CertificateObservationCount = 1,
                            ResolutionStatus = SubdomainResolutionStatus.Unknown
                        }
                    }
                    : Array.Empty<SubdomainDiscoveryEntry>();
                return Task.FromResult(discovered);
            },
            HttpsProbeOverride = (httpsTargets, options, logger, cancellationToken) => {
                var entries = new List<CertificateMonitor.Entry>();
                foreach (var target in httpsTargets) {
                    var uri = new Uri(target);
                    entries.Add(new CertificateMonitor.Entry {
                        Host = uri.Host,
                        ResolvedHost = uri.Host,
                        Url = target,
                        Scheme = uri.Scheme,
                        Port = uri.Port,
                        Service = "HTTPS",
                        Valid = false,
                        Expired = false,
                        ChainComplete = false,
                        Protocol = SslProtocols.None,
                        Analysis = new CertificateAnalysis {
                            Url = target,
                            IsReachable = false
                        }
                    });
                }
                return Task.FromResult<IReadOnlyList<CertificateMonitor.Entry>>(entries);
            }
        };

        var options = new CertificateInventoryCaptureOptions {
            IncludeApexHttps = true,
            IncludeWwwHttps = false,
            IncludeCtDiscoveredSubdomains = false,
            VerifyCtDiscoveredSubdomains = false,
            EnablePassiveCtFallback = false,
            EnablePassiveCtMetadataFallback = true,
            IncludeMxHosts = false,
            IncludeMxHttps = false,
            IncludeSmtpStartTls = false,
            IncludeSubmissionStartTls = false,
            IncludeImapTls = false,
            IncludePop3Tls = false,
            BackfillMissingCtCertificateMetadata = true,
            PersistSnapshot = false
        };

        var result = await capture.CaptureAsync(new[] { "airtoxics.eurofins.com" }, options, cancellationToken: CancellationToken.None);
        var endpoint = Assert.Single(result.Snapshot.Entries);
        Assert.Equal("airtoxics.eurofins.com", endpoint.Host);
        Assert.False(endpoint.IsReachable);
        Assert.True(endpoint.PresentInCtLogs);
        Assert.Equal("CN=airtoxics.eurofins.com", endpoint.CertificateSubject);
        Assert.Equal("CN=Sectigo RSA Domain Validation Secure Server CA, O=Sectigo Limited, C=GB", endpoint.CertificateIssuer);
        Assert.Equal("0CE4A3C00C1DD4890B9EBA4223FE917F", endpoint.CertificateSerialNumber);
        Assert.Equal(notBefore, endpoint.NotBeforeUtc);
        Assert.Equal(notAfter, endpoint.NotAfterUtc);
        Assert.Equal(ctEntryTimestamp, endpoint.CtLatestCertificateEntryTimestampUtc);
        Assert.Contains("crt.sh", endpoint.CtDiscoverySources, StringComparer.OrdinalIgnoreCase);
        Assert.Equal("ct-log", endpoint.CertificateChainSource);
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

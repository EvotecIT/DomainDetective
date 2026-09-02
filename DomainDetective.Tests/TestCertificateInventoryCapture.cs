using DnsClientX;
using DomainDetective.Providers.Endpoint;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

public class TestCertificateInventoryCapture {
    [Fact]
    public async Task CaptureAsync_SharesProbeStartLimitAcrossProtocolPhases() {
        var mailListener = new TcpListener(IPAddress.Loopback, 0);
        var ftpListener = new TcpListener(IPAddress.Loopback, 0);
        mailListener.Start();
        ftpListener.Start();
        int mailPort = ((IPEndPoint)mailListener.LocalEndpoint).Port;
        int ftpPort = ((IPEndPoint)ftpListener.LocalEndpoint).Port;
        Task mailServer = Task.Run(async () => {
            using TcpClient client = await mailListener.AcceptTcpClientAsync();
        });
        Task ftpServer = Task.Run(async () => {
            using TcpClient client = await ftpListener.AcceptTcpClientAsync();
        });

        try {
            var options = new CertificateInventoryCaptureOptions {
                IncludeApexHttps = false,
                IncludeWwwHttps = false,
                IncludeMxHosts = false,
                PersistSnapshot = false,
                MaxParallelism = 1,
                MaxProbeStartsPerSecond = 2,
                MailTimeout = TimeSpan.FromSeconds(1),
                FtpTlsTimeout = TimeSpan.FromSeconds(1)
            };
            options.AdditionalEndpoints.Add($"smtp://127.0.0.1:{mailPort}");
            options.AdditionalEndpoints.Add($"ftps-explicit://127.0.0.1:{ftpPort}");

            CertificateInventoryCaptureResult result = await new CertificateInventoryCapture().CaptureAsync(
                Array.Empty<string>(),
                options);

            Assert.Equal(1, result.ProbedMailCount);
            Assert.Equal(1, result.ProbedFtpTlsCount);
            CertificateInventoryEntry mailEntry = Assert.Single(
                result.Snapshot.Entries,
                entry => string.Equals(entry.Scheme, "smtp", StringComparison.OrdinalIgnoreCase));
            CertificateInventoryEntry ftpEntry = Assert.Single(
                result.Snapshot.Entries,
                entry => string.Equals(entry.Scheme, "ftps-explicit", StringComparison.OrdinalIgnoreCase));
            TimeSpan phaseBoundaryGap = ftpEntry.ObservedAtUtc!.Value - mailEntry.ObservedAtUtc!.Value;
            Assert.True(
                phaseBoundaryGap >= TimeSpan.FromMilliseconds(350),
                $"Expected the global probe-start interval across protocol phases; observed {phaseBoundaryGap}.");
        } finally {
            mailListener.Stop();
            ftpListener.Stop();
            await Task.WhenAll(mailServer, ftpServer);
        }
    }

    [Fact]
    public async Task CaptureAsync_EnrichesEndpointWithDnsEvidenceVantageAndAttribution() {
        using var certificate = CreateSelfSignedWithEku(CertificateExtendedKeyUsageAnalyzer.ServerAuthenticationOid);
        var capture = new CertificateInventoryCapture {
            HttpsProbeOverride = (targets, _, _, _) => {
                CertificateMonitor.Entry entry = CreateHttpsEntry(Assert.Single(targets), certificate);
                return Task.FromResult<IReadOnlyList<CertificateMonitor.Entry>>(new[] { entry });
            },
            EndpointDnsQueryOverride = (name, type, _) => {
                DnsAnswer[] answers = (name, type) switch {
                    ("service.example.com", DnsRecordType.CNAME) =>
                        new[] { new DnsAnswer { Type = DnsRecordType.CNAME, DataRaw = "tenant.azurefd.net." } },
                    ("tenant.azurefd.net", DnsRecordType.A) =>
                        new[] { new DnsAnswer { Type = DnsRecordType.A, DataRaw = "203.0.113.10" } },
                    _ => Array.Empty<DnsAnswer>()
                };
                return Task.FromResult(answers);
            }
        };
        var options = new CertificateInventoryCaptureOptions {
            IncludeApexHttps = false,
            IncludeWwwHttps = false,
            IncludeMxHosts = false,
            PersistSnapshot = false,
            EnableEndpointAttribution = true,
            ProbeVantage = "eu-test-vantage"
        };
        options.AdditionalEndpoints.Add("https://service.example.com");

        CertificateInventoryCaptureResult result = await capture.CaptureAsync(
            Array.Empty<string>(),
            options,
            cancellationToken: CancellationToken.None);

        CertificateInventoryEntry inventoryEntry = Assert.Single(result.Snapshot.Entries);
        Assert.NotNull(inventoryEntry.ObservedAtUtc);
        Assert.NotNull(inventoryEntry.DnsObservedAtUtc);
        Assert.Equal("eu-test-vantage", inventoryEntry.ProbeVantage);
        Assert.Contains("203.0.113.10", inventoryEntry.ResolvedAddresses);
        Assert.Equal(new[] { "tenant.azurefd.net" }, inventoryEntry.CnameChain);
        Providers.Endpoint.EndpointAttributionCandidate primary = Assert.IsType<Providers.Endpoint.EndpointAttributionCandidate>(inventoryEntry.Attribution?.Primary);
        Assert.Equal("azure-front-door", primary.ServiceId);
        Assert.True(inventoryEntry.Attribution!.EvaluatedAtUtc >= inventoryEntry.DnsObservedAtUtc!.Value);
        Assert.True(result.Snapshot.CapturedAtUtc >= inventoryEntry.DnsObservedAtUtc.Value);
        Assert.True(result.Snapshot.CapturedAtUtc >= inventoryEntry.Attribution.EvaluatedAtUtc);
        Assert.Equal(result.Snapshot.CapturedAtUtc, result.CapturedAtUtc);
        Assert.Contains(
            primary.Evidence,
            evidence => evidence.Kind == Providers.Endpoint.EndpointAttributionSignalKind.Cname);
    }

    [Fact]
    public async Task CaptureAsync_DoesNotBlendReusedRemotePeerIntoFreshAttribution() {
        var cachedEntry = new CertificateInventoryEntry {
            Host = "service.example.com",
            ResolvedHost = "service.example.com",
            Url = "https://service.example.com/",
            Scheme = "https",
            Port = 443,
            Service = "HTTPS",
            ObservedAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10),
            RemoteAddress = "192.0.2.10",
            RemoteAddressFamily = "IPv4",
            CertificateThumbprint = "CACHED-CERT",
            IsReachable = true,
            Valid = true,
            NotAfterUtc = DateTimeOffset.UtcNow.AddDays(90)
        };
        var capture = new CertificateInventoryCapture {
            RecentSnapshotLookupOverride = (_, _, _) =>
                new Dictionary<string, CertificateInventoryEntry>(StringComparer.OrdinalIgnoreCase) {
                    ["service.example.com|443|HTTPS"] = cachedEntry
                },
            HttpsProbeOverride = (targets, _, _, _) => {
                Assert.Empty(targets);
                return Task.FromResult<IReadOnlyList<CertificateMonitor.Entry>>(Array.Empty<CertificateMonitor.Entry>());
            },
            EndpointDnsQueryOverride = (_, type, _) => Task.FromResult(
                type == DnsRecordType.A
                    ? new[] { new DnsAnswer { Type = DnsRecordType.A, DataRaw = "198.51.100.20" } }
                    : Array.Empty<DnsAnswer>())
        };
        var options = new CertificateInventoryCaptureOptions {
            IncludeApexHttps = false,
            IncludeWwwHttps = false,
            IncludeMxHosts = false,
            PersistSnapshot = false,
            EnableEndpointAttribution = true,
            ReuseRecentSnapshotEntries = true,
            RecentSnapshotTtl = TimeSpan.FromHours(1)
        };
        foreach ((string ruleId, string prefix) in new[] {
            ("custom.stale-peer", "192.0.2.0/24"),
            ("custom.fresh-dns", "198.51.100.0/24")
        }) {
            var rule = new EndpointAttributionRule {
                RuleId = ruleId,
                RuleVersion = "1",
                ProviderId = "example",
                ServiceId = ruleId,
                DisplayName = ruleId
            };
            rule.IpAddressPrefixes.Add(prefix);
            options.EndpointAttributionRules.Add(rule);
        }
        options.AdditionalEndpoints.Add("https://service.example.com");

        CertificateInventoryCaptureResult result = await capture.CaptureAsync(Array.Empty<string>(), options);

        CertificateInventoryEntry entry = Assert.Single(result.Snapshot.Entries);
        Assert.Equal("reused-recent-success", entry.CaptureDisposition);
        Assert.Equal("192.0.2.10", entry.RemoteAddress);
        Assert.Contains("198.51.100.20", entry.ResolvedAddresses);
        Assert.DoesNotContain(entry.Attribution!.Candidates, candidate => candidate.RuleId == "custom.stale-peer");
        Assert.Contains(entry.Attribution.Candidates, candidate => candidate.RuleId == "custom.fresh-dns");
        Assert.Equal("custom.fresh-dns", entry.Attribution.Primary?.RuleId);
    }

    [Fact]
    public async Task CaptureAsync_BoundsConcurrentDnsEnrichmentWithWorkerPool() {
        using var certificate = CreateSelfSignedWithEku(CertificateExtendedKeyUsageAnalyzer.ServerAuthenticationOid);
        int activeQueries = 0;
        int maximumActiveQueries = 0;
        var capture = new CertificateInventoryCapture {
            HttpsProbeOverride = (targets, _, _, _) => {
                var entries = new List<CertificateMonitor.Entry>(targets.Count);
                foreach (string target in targets) {
                    entries.Add(CreateHttpsEntry(target, certificate));
                }
                return Task.FromResult<IReadOnlyList<CertificateMonitor.Entry>>(entries);
            },
            EndpointDnsQueryOverride = async (_, _, cancellationToken) => {
                int active = Interlocked.Increment(ref activeQueries);
                int observedMaximum;
                do {
                    observedMaximum = Volatile.Read(ref maximumActiveQueries);
                    if (active <= observedMaximum) {
                        break;
                    }
                } while (Interlocked.CompareExchange(
                    ref maximumActiveQueries,
                    active,
                    observedMaximum) != observedMaximum);

                try {
                    await Task.Delay(10, cancellationToken);
                    return Array.Empty<DnsAnswer>();
                } finally {
                    Interlocked.Decrement(ref activeQueries);
                }
            }
        };
        var options = new CertificateInventoryCaptureOptions {
            IncludeApexHttps = false,
            IncludeWwwHttps = false,
            IncludeMxHosts = false,
            PersistSnapshot = false,
            EnableEndpointAttribution = true,
            DnsEnrichmentParallelism = 3
        };
        for (int host = 0; host < 20; host++) {
            options.AdditionalEndpoints.Add($"https://service-{host}.example.com");
        }

        CertificateInventoryCaptureResult result = await capture.CaptureAsync(Array.Empty<string>(), options);

        Assert.Equal(20, result.Snapshot.Entries.Count);
        Assert.InRange(maximumActiveQueries, 2, options.DnsEnrichmentParallelism);
    }

    [Theory]
    [InlineData(true, nameof(EndpointAttributionRule.ReverseDnsSuffixes))]
    [InlineData(false, nameof(EndpointAttributionRule.AutonomousSystemNumbers))]
    public async Task CaptureAsync_RejectsCustomAttributionSignalsItCannotCollectBeforeProbing(
        bool useReverseDns,
        string expectedSignal) {
        int probeCalls = 0;
        var capture = new CertificateInventoryCapture {
            HttpsProbeOverride = (_, _, _, _) => {
                probeCalls++;
                return Task.FromResult<IReadOnlyList<CertificateMonitor.Entry>>(Array.Empty<CertificateMonitor.Entry>());
            }
        };
        var options = new CertificateInventoryCaptureOptions {
            IncludeApexHttps = false,
            IncludeWwwHttps = false,
            IncludeMxHosts = false,
            PersistSnapshot = false,
            EnableEndpointAttribution = true
        };
        var rule = new EndpointAttributionRule {
            RuleId = "custom.unsupported-capture-signal",
            RuleVersion = "1",
            ProviderId = "example",
            ServiceId = "edge",
            DisplayName = "Example Edge"
        };
        if (useReverseDns) {
            rule.ReverseDnsSuffixes.Add("edge.example.net");
        } else {
            rule.AutonomousSystemNumbers.Add("64500");
        }
        options.EndpointAttributionRules.Add(rule);
        options.AdditionalEndpoints.Add("https://service.example.com");

        NotSupportedException exception = await Assert.ThrowsAsync<NotSupportedException>(() =>
            capture.CaptureAsync(Array.Empty<string>(), options));

        Assert.Equal(0, probeCalls);
        Assert.Contains("custom.unsupported-capture-signal", exception.Message, StringComparison.Ordinal);
        Assert.Contains(expectedSignal, exception.Message, StringComparison.Ordinal);
        Assert.Contains(nameof(EndpointAttributionDetector), exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CaptureAsync_DoesNotReuseObservationFromAnotherVantage() {
        const int port = 1;
        var capture = new CertificateInventoryCapture {
            RecentSnapshotLookupOverride = (_, _, _) =>
                new Dictionary<string, CertificateInventoryEntry>(StringComparer.OrdinalIgnoreCase) {
                    ["localhost|1|FTPS-EXPLICIT"] = new CertificateInventoryEntry {
                        Host = "localhost",
                        ResolvedHost = "localhost",
                        Port = port,
                        Service = "FTPS-EXPLICIT",
                        Scheme = "ftps-explicit",
                        ProbeVantage = "cloud",
                        IsReachable = true,
                        Valid = true,
                        CertificateThumbprint = "CACHED",
                        NotAfterUtc = DateTimeOffset.UtcNow.AddDays(90)
                    }
                }
        };
        var options = new CertificateInventoryCaptureOptions {
            IncludeApexHttps = false,
            IncludeWwwHttps = false,
            IncludeMxHosts = false,
            PersistSnapshot = false,
            ReuseRecentSnapshotEntries = true,
            RecentSnapshotTtl = TimeSpan.FromHours(1),
            ProbeVantage = "branch-office",
            FtpTlsTimeout = TimeSpan.FromSeconds(1)
        };
        options.AdditionalEndpoints.Add($"ftps-explicit://localhost:{port}");

        CertificateInventoryCaptureResult result = await capture.CaptureAsync(Array.Empty<string>(), options);

        Assert.Equal(0, result.ReusedRecentEntryCount);
        Assert.Equal(1, result.ProbedFtpTlsCount);
        Assert.Equal("branch-office", Assert.Single(result.Snapshot.Entries).ProbeVantage);
    }

    [Fact]
    public async Task CaptureAsync_ReusesRecentFtpTlsObservationWithinSameVantage() {
        const int port = 2121;
        var cachedEntry = new CertificateInventoryEntry {
            Host = "ftp.example.com",
            ResolvedHost = "ftp.example.com",
            Port = port,
            Service = "FTPS-EXPLICIT",
            Scheme = "ftps-explicit",
            ProbeVantage = "branch-office",
            RemoteAddress = "::ffff:192.0.2.50",
            RemoteAddressFamily = "InterNetworkV6",
            IsReachable = true,
            Valid = true,
            CertificateThumbprint = "CACHED-FTPS",
            NotAfterUtc = DateTimeOffset.UtcNow.AddDays(90)
        };
        var capture = new CertificateInventoryCapture {
            RecentSnapshotLookupOverride = (_, _, _) =>
                new Dictionary<string, CertificateInventoryEntry>(StringComparer.OrdinalIgnoreCase) {
                    ["ftp.example.com|2121|FTPS-EXPLICIT"] = cachedEntry
                }
        };
        var options = new CertificateInventoryCaptureOptions {
            IncludeApexHttps = false,
            IncludeWwwHttps = false,
            IncludeMxHosts = false,
            PersistSnapshot = false,
            ReuseRecentSnapshotEntries = true,
            RecentSnapshotTtl = TimeSpan.FromHours(1),
            ProbeVantage = "branch-office"
        };
        options.AdditionalEndpoints.Add($"ftps-explicit://ftp.example.com:{port}");

        CertificateInventoryCaptureResult result = await capture.CaptureAsync(Array.Empty<string>(), options);

        Assert.Equal(1, result.ReusedRecentEntryCount);
        Assert.Equal(1, result.ReusedRecentFtpTlsCount);
        Assert.Equal(0, result.FtpTlsEndpointCount);
        Assert.Equal(0, result.ProbedFtpTlsCount);
        Assert.Empty(result.FtpTlsEndpoints);
        CertificateInventoryEntry reused = Assert.Single(result.Snapshot.Entries);
        Assert.Equal("reused-recent-success", reused.CaptureDisposition);
        Assert.Equal("192.0.2.50", reused.RemoteAddress);
        Assert.Equal("IPv4", reused.RemoteAddressFamily);
    }

    [Fact]
    public async Task CaptureAsync_DoesNotRefreshFtpTlsReuseAgeFromNewerSnapshotTime() {
        const int port = 1;
        var capture = new CertificateInventoryCapture {
            RecentSnapshotLookupOverride = (_, _, _) =>
                new Dictionary<string, CertificateInventoryEntry>(StringComparer.OrdinalIgnoreCase) {
                    ["localhost|1|FTPS-EXPLICIT"] = new CertificateInventoryEntry {
                        Host = "localhost",
                        ResolvedHost = "localhost",
                        Port = port,
                        Service = "FTPS-EXPLICIT",
                        Scheme = "ftps-explicit",
                        ProbeVantage = "default",
                        ObservedAtUtc = DateTimeOffset.UtcNow.AddHours(-2),
                        IsReachable = true,
                        Valid = true,
                        CertificateThumbprint = "STALE-FTPS",
                        NotAfterUtc = DateTimeOffset.UtcNow.AddDays(90)
                    }
                }
        };
        var options = new CertificateInventoryCaptureOptions {
            IncludeApexHttps = false,
            IncludeWwwHttps = false,
            IncludeMxHosts = false,
            PersistSnapshot = false,
            ReuseRecentSnapshotEntries = true,
            RecentSnapshotTtl = TimeSpan.FromHours(1),
            FtpTlsTimeout = TimeSpan.FromSeconds(1)
        };
        options.AdditionalEndpoints.Add($"ftps-explicit://localhost:{port}");

        CertificateInventoryCaptureResult result = await capture.CaptureAsync(Array.Empty<string>(), options);

        Assert.Equal(0, result.ReusedRecentFtpTlsCount);
        Assert.Equal(1, result.ProbedFtpTlsCount);
        Assert.Equal("live-probe", Assert.Single(result.Snapshot.Entries).CaptureDisposition);
    }

    [Fact]
    public async Task CaptureAsync_DoesNotRefreshHttpsFailureReuseAgeFromNewerSnapshotTime() {
        int observedProbeTargets = 0;
        var capture = new CertificateInventoryCapture {
            RecentSnapshotLookupOverride = (_, _, _) =>
                new Dictionary<string, CertificateInventoryEntry>(StringComparer.OrdinalIgnoreCase) {
                    ["localhost|1|CUSTOM TLS"] = new CertificateInventoryEntry {
                        Host = "localhost",
                        ResolvedHost = "localhost",
                        Port = 1,
                        Service = "Custom TLS",
                        Scheme = "https",
                        ProbeVantage = "default",
                        ObservedAtUtc = DateTimeOffset.UtcNow.AddHours(-2),
                        IsReachable = false,
                        FailureKind = CertificateFailureKind.ConnectionRefused,
                        FailureReason = "Connection refused"
                    }
                },
            HttpsProbeOverride = (targets, _, _, _) => {
                observedProbeTargets = targets.Count;
                return Task.FromResult<IReadOnlyList<CertificateMonitor.Entry>>(Array.Empty<CertificateMonitor.Entry>());
            }
        };
        var options = new CertificateInventoryCaptureOptions {
            IncludeApexHttps = false,
            IncludeWwwHttps = false,
            IncludeMxHosts = false,
            PersistSnapshot = false,
            ReuseRecentFailureSnapshotEntries = true,
            RecentFailureSnapshotTtl = TimeSpan.FromHours(1)
        };
        options.AdditionalEndpoints.Add("https://localhost:1");

        CertificateInventoryCaptureResult result = await capture.CaptureAsync(Array.Empty<string>(), options);

        Assert.Equal(0, result.ReusedRecentFailureHttpsCount);
        Assert.Equal(1, result.ProbedHttpsCount);
        Assert.Equal(1, observedProbeTargets);
    }

    [Fact]
    public async Task CaptureAsync_PrioritizesUncachedFtpTlsTargetBeforeReusableHighPriorityCachedTarget() {
        var capture = new CertificateInventoryCapture {
            RecentSnapshotLookupOverride = (_, _, _) =>
                new Dictionary<string, CertificateInventoryEntry>(StringComparer.OrdinalIgnoreCase) {
                    ["localhost|1|FTPS-EXPLICIT"] = new CertificateInventoryEntry {
                        Host = "localhost",
                        ResolvedHost = "localhost",
                        Port = 1,
                        Service = "FTPS-EXPLICIT",
                        Scheme = "ftps-explicit",
                        ProbeVantage = "default",
                        ObservedAtUtc = DateTimeOffset.UtcNow,
                        IsReachable = true,
                        Valid = true,
                        IsKnownCertificateAuthority = true,
                        AllowsServerAuthentication = true,
                        // A reusable observation can legitimately carry a high evidence
                        // score without requiring a fresh probe.
                        PresentInCtLogs = false,
                        CertificateThumbprint = "HEALTHY-CACHED-FTPS",
                        NotAfterUtc = DateTimeOffset.UtcNow.AddDays(180)
                    }
                }
        };
        var options = new CertificateInventoryCaptureOptions {
            IncludeApexHttps = false,
            IncludeWwwHttps = false,
            IncludeMxHosts = false,
            PersistSnapshot = false,
            ReuseRecentSnapshotEntries = true,
            RecentSnapshotTtl = TimeSpan.FromHours(1),
            MaxTargets = 1,
            FtpTlsTimeout = TimeSpan.FromSeconds(1)
        };
        options.AdditionalEndpoints.Add("ftps-explicit://localhost:1");
        options.AdditionalEndpoints.Add("ftps-explicit://localhost:2");

        CertificateInventoryCaptureResult result = await capture.CaptureAsync(Array.Empty<string>(), options);

        Assert.Equal(0, result.ReusedRecentFtpTlsCount);
        Assert.Equal(1, result.ProbedFtpTlsCount);
        Assert.Equal(1, result.FtpTlsTargetCountDroppedByLimit);
        Assert.Equal("ftps-explicit://localhost:2", Assert.Single(result.FtpTlsEndpoints));
    }

    [Fact]
    public async Task CaptureAsync_ReusableFtpTlsFailureDoesNotConsumeLiveProbeBudget() {
        var capture = new CertificateInventoryCapture {
            RecentSnapshotLookupOverride = (_, _, _) =>
                new Dictionary<string, CertificateInventoryEntry>(StringComparer.OrdinalIgnoreCase) {
                    ["localhost|1|FTPS-EXPLICIT"] = new CertificateInventoryEntry {
                        Host = "localhost",
                        ResolvedHost = "localhost",
                        Port = 1,
                        Service = "FTPS-EXPLICIT",
                        Scheme = "ftps-explicit",
                        ProbeVantage = "default",
                        ObservedAtUtc = DateTimeOffset.UtcNow,
                        IsReachable = false,
                        FailureKind = CertificateFailureKind.ConnectionRefused,
                        FailureReason = "Connection refused"
                    }
                }
        };
        var options = new CertificateInventoryCaptureOptions {
            IncludeApexHttps = false,
            IncludeWwwHttps = false,
            IncludeMxHosts = false,
            PersistSnapshot = false,
            ReuseRecentFailureSnapshotEntries = true,
            RecentFailureSnapshotTtl = TimeSpan.FromHours(1),
            MaxTargets = 1,
            FtpTlsTimeout = TimeSpan.FromSeconds(1)
        };
        options.AdditionalEndpoints.Add("ftps-explicit://localhost:1");
        options.AdditionalEndpoints.Add("ftps-explicit://localhost:2");

        CertificateInventoryCaptureResult result = await capture.CaptureAsync(Array.Empty<string>(), options);

        Assert.Equal(1, result.ReusedRecentFtpTlsCount);
        Assert.Equal(1, result.ReusedRecentFailureFtpTlsCount);
        Assert.Equal(1, result.ProbedFtpTlsCount);
        Assert.Equal(0, result.FtpTlsTargetCountDroppedByLimit);
        Assert.Equal("ftps-explicit://localhost:2", Assert.Single(result.FtpTlsEndpoints));
        Assert.Contains(result.Snapshot.Entries, entry =>
            entry.Port == 1 && entry.CaptureDisposition == "reused-recent-stable-failure");
    }

    [Fact]
    public async Task CaptureAsync_BracketedIpv6MailTargetRetainsCompletedProbeResult() {
        var capture = new CertificateInventoryCapture();
        var options = new CertificateInventoryCaptureOptions {
            IncludeApexHttps = false,
            IncludeWwwHttps = false,
            IncludeMxHosts = false,
            PersistSnapshot = false,
            MailTimeout = TimeSpan.FromSeconds(1)
        };
        options.AdditionalEndpoints.Add("[::1]:25");

        CertificateInventoryCaptureResult result = await capture.CaptureAsync(Array.Empty<string>(), options);

        Assert.Equal(1, result.ProbedMailCount);
        Assert.Equal("smtp://[::1]:25", Assert.Single(result.MailEndpoints));
        CertificateInventoryEntry entry = Assert.Single(result.Snapshot.Entries);
        Assert.Equal("::1", entry.Host);
        Assert.True(
            entry.FailureKind != CertificateFailureKind.None ||
            entry.IsReachable ||
            !string.IsNullOrWhiteSpace(entry.CertificateThumbprint));
        if (entry.FailureKind != CertificateFailureKind.None) {
            Assert.False(string.IsNullOrWhiteSpace(entry.FailureReason));
        }
    }

    [Theory]
    [InlineData("[2001:db8::10]:8443", "https://[2001:db8::10]:8443/")]
    [InlineData("[2001:db8::10]", "https://[2001:db8::10]/")]
    [InlineData("2001:db8::10", "https://[2001:db8::10]/")]
    public async Task CaptureAsync_Ipv6HttpsEndpointRetainsUriAuthority(string endpoint, string expectedUrl) {
        IReadOnlyList<string>? observedTargets = null;
        var capture = new CertificateInventoryCapture {
            HttpsProbeOverride = (targets, _, _, _) => {
                observedTargets = targets;
                return Task.FromResult<IReadOnlyList<CertificateMonitor.Entry>>(
                    Array.Empty<CertificateMonitor.Entry>());
            }
        };
        var options = new CertificateInventoryCaptureOptions {
            IncludeApexHttps = false,
            IncludeWwwHttps = false,
            IncludeMxHosts = false,
            PersistSnapshot = false
        };
        options.AdditionalEndpoints.Add(endpoint);

        CertificateInventoryCaptureResult result = await capture.CaptureAsync(Array.Empty<string>(), options);

        Assert.Equal(expectedUrl, Assert.Single(observedTargets!));
        Assert.Equal(expectedUrl, Assert.Single(result.HttpsEndpoints));
        Assert.Empty(result.Warnings);
    }

    [Theory]
    [InlineData("ftps://localhost:0")]
    [InlineData("ftps-explicit://localhost:0")]
    [InlineData("smtp://localhost:0")]
    [InlineData("submission://localhost:0")]
    [InlineData("imap://localhost:0")]
    [InlineData("imaps://localhost:0")]
    [InlineData("pop3://localhost:0")]
    [InlineData("pop3s://localhost:0")]
    [InlineData("https://localhost:0")]
    public async Task CaptureAsync_RejectsExplicitZeroPortEndpoint(string endpoint) {
        var options = new CertificateInventoryCaptureOptions {
            IncludeApexHttps = false,
            IncludeWwwHttps = false,
            IncludeMxHosts = false,
            PersistSnapshot = false
        };
        options.AdditionalEndpoints.Add(endpoint);

        CertificateInventoryCaptureResult result = await new CertificateInventoryCapture().CaptureAsync(
            Array.Empty<string>(),
            options);

        Assert.Equal(0, result.FtpTlsEndpointCount);
        Assert.Equal(0, result.MailEndpointCount);
        Assert.Equal(0, result.HttpsEndpointCount);
        Assert.Empty(result.Snapshot.Entries);
        Assert.Contains(result.Warnings, warning => warning.Contains("invalid endpoint", StringComparison.OrdinalIgnoreCase));
        TargetDecisionDiagnosticEntry diagnostic = Assert.Single(result.TargetDecisionDiagnostics);
        Assert.Equal("invalid-endpoint", diagnostic.Reason);
        Assert.Equal(endpoint, diagnostic.Target);
    }

    [Theory]
    [InlineData("[mail.example.com]:25")]
    [InlineData("[www.example.com]")]
    [InlineData("smtp://[mail.example.com]:25")]
    public async Task CaptureAsync_RejectsBracketsAroundDnsHostname(string endpoint) {
        var capture = new CertificateInventoryCapture {
            HttpsProbeOverride = (targets, _, _, _) => {
                Assert.Empty(targets);
                return Task.FromResult<IReadOnlyList<CertificateMonitor.Entry>>(
                    Array.Empty<CertificateMonitor.Entry>());
            }
        };
        var options = new CertificateInventoryCaptureOptions {
            IncludeApexHttps = false,
            IncludeWwwHttps = false,
            IncludeMxHosts = false,
            PersistSnapshot = false
        };
        options.AdditionalEndpoints.Add(endpoint);

        CertificateInventoryCaptureResult result = await capture.CaptureAsync(Array.Empty<string>(), options);

        Assert.Empty(result.Snapshot.Entries);
        Assert.Contains(result.Warnings, warning => warning.Contains("invalid endpoint", StringComparison.OrdinalIgnoreCase));
        TargetDecisionDiagnosticEntry diagnostic = Assert.Single(result.TargetDecisionDiagnostics);
        Assert.Equal("invalid-endpoint", diagnostic.Reason);
        Assert.Equal(endpoint, diagnostic.Target);
    }

    [Fact]
    public async Task CaptureAsync_PrioritizesStaleFtpTlsTargetBeforeReusableHealthyTarget() {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        CertificateInventoryEntry Cached(int port, DateTimeOffset observedAtUtc, string thumbprint) => new() {
            Host = "localhost",
            ResolvedHost = "localhost",
            Port = port,
            Service = "FTPS-EXPLICIT",
            Scheme = "ftps-explicit",
            ProbeVantage = "default",
            ObservedAtUtc = observedAtUtc,
            IsReachable = true,
            Valid = true,
            IsKnownCertificateAuthority = true,
            AllowsServerAuthentication = true,
            PresentInCtLogs = true,
            CertificateThumbprint = thumbprint,
            NotAfterUtc = now.AddDays(180)
        };
        var capture = new CertificateInventoryCapture {
            RecentSnapshotLookupOverride = (_, _, _) =>
                new Dictionary<string, CertificateInventoryEntry>(StringComparer.OrdinalIgnoreCase) {
                    ["localhost|1|FTPS-EXPLICIT"] = Cached(1, now, "REUSABLE-FTPS"),
                    ["localhost|2|FTPS-EXPLICIT"] = Cached(2, now.AddHours(-2), "STALE-FTPS")
                }
        };
        var options = new CertificateInventoryCaptureOptions {
            IncludeApexHttps = false,
            IncludeWwwHttps = false,
            IncludeMxHosts = false,
            PersistSnapshot = false,
            ReuseRecentSnapshotEntries = true,
            RecentSnapshotTtl = TimeSpan.FromHours(1),
            MaxTargets = 1,
            FtpTlsTimeout = TimeSpan.FromSeconds(1)
        };
        options.AdditionalEndpoints.Add("ftps-explicit://localhost:1");
        options.AdditionalEndpoints.Add("ftps-explicit://localhost:2");

        CertificateInventoryCaptureResult result = await capture.CaptureAsync(Array.Empty<string>(), options);

        Assert.Equal(0, result.ReusedRecentFtpTlsCount);
        Assert.Equal(1, result.ProbedFtpTlsCount);
        Assert.Equal("ftps-explicit://localhost:2", Assert.Single(result.FtpTlsEndpoints));
    }

    [Fact]
    public async Task CaptureAsync_MixedVantageHistoryRetainsRequestedVantageEntry() {
        string cacheDirectory = Path.Combine(Path.GetTempPath(), "dd-vantage-cache-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(cacheDirectory);
        try {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            foreach ((string vantage, DateTimeOffset capturedAt, string thumbprint) in new[] {
                ("branch-office", now.AddMinutes(-20), "BRANCH-CERT"),
                ("cloud", now.AddMinutes(-10), "CLOUD-CERT")
            }) {
                var snapshot = new CertificateInventorySnapshot { CapturedAtUtc = capturedAt, Port = 443 };
                snapshot.Entries.Add(new CertificateInventoryEntry {
                    Host = "service.example.com",
                    ResolvedHost = "service.example.com",
                    Port = 443,
                    Service = "HTTPS",
                    Scheme = "https",
                    ProbeVantage = vantage,
                    ObservedAtUtc = capturedAt,
                    IsReachable = true,
                    Valid = true,
                    CertificateThumbprint = thumbprint,
                    NotAfterUtc = now.AddDays(90)
                });
                using var monitor = new CertificateMonitor { CacheDirectory = cacheDirectory, PersistInventorySnapshots = false };
                monitor.SaveInventorySnapshot(snapshot);
            }

            int probedTargetCount = -1;
            var capture = new CertificateInventoryCapture {
                HttpsProbeOverride = (targets, _, _, _) => {
                    probedTargetCount = targets.Count;
                    return Task.FromResult<IReadOnlyList<CertificateMonitor.Entry>>(Array.Empty<CertificateMonitor.Entry>());
                }
            };
            var options = new CertificateInventoryCaptureOptions {
                CacheDirectory = cacheDirectory,
                IncludeApexHttps = false,
                IncludeWwwHttps = false,
                IncludeMxHosts = false,
                PersistSnapshot = false,
                ReuseRecentSnapshotEntries = true,
                RecentSnapshotTtl = TimeSpan.FromHours(1),
                ProbeVantage = "branch-office"
            };
            options.AdditionalEndpoints.Add("https://service.example.com");

            CertificateInventoryCaptureResult result = await capture.CaptureAsync(Array.Empty<string>(), options);

            Assert.Equal(0, probedTargetCount);
            Assert.Equal(1, result.ReusedRecentHttpsCount);
            CertificateInventoryEntry entry = Assert.Single(result.Snapshot.Entries);
            Assert.Equal("BRANCH-CERT", entry.CertificateThumbprint);
            Assert.Equal("branch-office", entry.ProbeVantage);
        } finally {
            Directory.Delete(cacheDirectory, recursive: true);
        }
    }

    [Theory]
    [InlineData("{not-json")]
    [InlineData("{\"values\":[null]}")]
    [InlineData("{\"values\":[{\"name\":\"AzureFrontDoor.Frontend\",\"properties\":{}}]}")]
    [InlineData("{\"values\":[{\"name\":123,\"properties\":{\"addressPrefixes\":[]}}]}")]
    public async Task CaptureAsync_MalformedOptionalAzureCatalogBecomesWarning(string malformedCatalog) {
        string path = Path.Combine(Path.GetTempPath(), "dd-invalid-azure-" + Guid.NewGuid().ToString("N") + ".json");
        File.WriteAllText(path, malformedCatalog);
        try {
            using var certificate = CreateSelfSignedWithEku(CertificateExtendedKeyUsageAnalyzer.ServerAuthenticationOid);
            var capture = new CertificateInventoryCapture {
                HttpsProbeOverride = (targets, _, _, _) =>
                    Task.FromResult<IReadOnlyList<CertificateMonitor.Entry>>(new[] { CreateHttpsEntry(Assert.Single(targets), certificate) }),
                EndpointDnsQueryOverride = (_, _, _) => Task.FromResult(Array.Empty<DnsAnswer>())
            };
            var options = new CertificateInventoryCaptureOptions {
                IncludeApexHttps = false,
                IncludeWwwHttps = false,
                IncludeMxHosts = false,
                PersistSnapshot = false,
                EnableEndpointAttribution = true,
                AzureServiceTagsJsonPath = path
            };
            options.AdditionalEndpoints.Add("https://service.example.com");

            CertificateInventoryCaptureResult result = await capture.CaptureAsync(Array.Empty<string>(), options);

            Assert.Single(result.Snapshot.Entries);
            Assert.Contains(result.Warnings, warning => warning.Contains("could not be loaded", StringComparison.OrdinalIgnoreCase));
        } finally {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task CaptureAsync_DuplicateAzureServiceTagsBecomeWarning() {
        string path = Path.Combine(Path.GetTempPath(), "dd-duplicate-azure-" + Guid.NewGuid().ToString("N") + ".json");
        File.WriteAllText(path, "{\"changeNumber\":\"7\",\"cloud\":\"Public\",\"values\":[{\"name\":\"AzureFrontDoor.Frontend\",\"properties\":{\"addressPrefixes\":[\"203.0.113.0/24\"]}},{\"name\":\"AzureFrontDoor.Frontend\",\"properties\":{\"addressPrefixes\":[\"2001:db8::/32\"]}}]}");
        try {
            using var certificate = CreateSelfSignedWithEku(CertificateExtendedKeyUsageAnalyzer.ServerAuthenticationOid);
            var capture = new CertificateInventoryCapture {
                HttpsProbeOverride = (targets, _, _, _) =>
                    Task.FromResult<IReadOnlyList<CertificateMonitor.Entry>>(new[] { CreateHttpsEntry(Assert.Single(targets), certificate) }),
                EndpointDnsQueryOverride = (_, _, _) => Task.FromResult(Array.Empty<DnsAnswer>())
            };
            var options = new CertificateInventoryCaptureOptions {
                IncludeApexHttps = false,
                IncludeWwwHttps = false,
                IncludeMxHosts = false,
                PersistSnapshot = false,
                EnableEndpointAttribution = true,
                AzureServiceTagsJsonPath = path
            };
            options.AdditionalEndpoints.Add("https://service.example.com");

            CertificateInventoryCaptureResult result = await capture.CaptureAsync(Array.Empty<string>(), options);

            Assert.Single(result.Snapshot.Entries);
            Assert.Contains(result.Warnings, warning =>
                warning.Contains("duplicate service-tag names", StringComparison.OrdinalIgnoreCase));
        } finally {
            File.Delete(path);
        }
    }

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
        Assert.Equal(0, result.MxInvalidArtifactCount);
        Assert.Equal(1, result.MxDuplicateHostCount);
        Assert.Equal(3, result.MxPromotedHttpsCount);
        Assert.Equal(0, result.MxSkippedDuplicateHttpsPromotionCount);
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
        Assert.Equal(8, result.CaptureDispositionCounts["live-probe"]);
        Assert.Equal(2, result.TargetOriginCounts["seed-apex"]);
        Assert.Equal(2, result.TargetOriginCounts["seed-www"]);
        Assert.Equal(3, result.TargetOriginCounts["mx-https"]);
        Assert.Equal(1, result.TargetOriginCounts["additional-endpoint"]);
        Assert.Contains(result.Snapshot.Entries, entry =>
            entry.Host.Equals("api.example.com", StringComparison.OrdinalIgnoreCase) &&
            entry.TargetOrigins.Contains("additional-endpoint", StringComparer.OrdinalIgnoreCase) &&
            entry.CaptureDisposition == "live-probe");
        Assert.Contains(result.Snapshot.Entries, entry =>
            entry.Host.Equals("mx1.example.com", StringComparison.OrdinalIgnoreCase) &&
            entry.TargetOrigins.Contains("mx-https", StringComparer.OrdinalIgnoreCase) &&
            entry.CaptureDisposition == "live-probe");
        var unsupportedScheme = Assert.Single(result.TargetDecisionDiagnostics);
        Assert.Equal("additional-endpoints", unsupportedScheme.Stage);
        Assert.Equal("rejected", unsupportedScheme.Action);
        Assert.Equal("unsupported-scheme", unsupportedScheme.Reason);
        Assert.Equal("warning", unsupportedScheme.Severity);
        Assert.Equal("Use a supported HTTPS or mail endpoint scheme.", unsupportedScheme.RecommendedAction);
        Assert.Equal("ftp://unsupported.example.com", unsupportedScheme.Target);
        var unsupportedSummary = Assert.Single(result.TargetDecisionSummary);
        Assert.Equal("additional-endpoints", unsupportedSummary.Stage);
        Assert.Equal("rejected", unsupportedSummary.Action);
        Assert.Equal("unsupported-scheme", unsupportedSummary.Reason);
        Assert.Equal("warning", unsupportedSummary.Severity);
        Assert.Equal("Use a supported HTTPS or mail endpoint scheme.", unsupportedSummary.RecommendedAction);
        Assert.Equal(1, unsupportedSummary.Count);
        Assert.Contains("ftp://unsupported.example.com", unsupportedSummary.ExampleTargets, StringComparer.OrdinalIgnoreCase);
        Assert.Contains(result.Warnings, warning => warning.Contains("Skipping invalid domain", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(result.Warnings, warning => warning.Contains("unsupported endpoint scheme", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task CaptureAsync_TracksMxSourceDomainsByHost() {
        var capture = new CertificateInventoryCapture {
            MxLookupOverride = (domain, dnsConfiguration, maxMxHostsPerDomain, cancellationToken) => {
                IReadOnlyList<string> hosts = domain.Equals("example.com", StringComparison.OrdinalIgnoreCase)
                    ? new[] { "mx.shared.example.", " MX.SHARED.EXAMPLE ", "not a valid host" }
                    : new[] { "mx.shared.example", "mx.contoso.example." };
                return Task.FromResult(hosts);
            },
            HttpsProbeOverride = (httpsTargets, options, logger, cancellationToken) =>
                Task.FromResult<IReadOnlyList<CertificateMonitor.Entry>>(Array.Empty<CertificateMonitor.Entry>())
        };

        var options = new CertificateInventoryCaptureOptions {
            IncludeApexHttps = false,
            IncludeWwwHttps = false,
            IncludeMxHosts = true,
            IncludeMxHttps = false,
            IncludeSmtpStartTls = false,
            IncludeSubmissionStartTls = false,
            IncludeImapTls = false,
            IncludePop3Tls = false,
            PersistSnapshot = false
        };

        var result = await capture.CaptureAsync(new[] { "example.com", "contoso.com" }, options, cancellationToken: CancellationToken.None);

        Assert.Equal(2, result.MxHostCount);
        Assert.Equal(1, result.MxInvalidArtifactCount);
        Assert.Equal(2, result.MxSourceDomainsByHost.Count);
        Assert.True(result.MxSourceDomainsByHost.TryGetValue("mx.shared.example", out IReadOnlyList<string>? sharedSources));
        Assert.Equal(new[] { "contoso.com", "example.com" }, sharedSources);
        Assert.True(result.MxSourceDomainsByHost.TryGetValue("mx.contoso.example", out IReadOnlyList<string>? contosoSources));
        Assert.Equal(new[] { "contoso.com" }, contosoSources);
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
        Assert.Contains("additional-endpoint", result.Snapshot.Entries[0].TargetOrigins, StringComparer.OrdinalIgnoreCase);
        Assert.Equal("live-probe", result.Snapshot.Entries[0].CaptureDisposition);
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
        Assert.Equal(2, result.CtPromotedHttpsCount);
        Assert.Equal(0, result.CtSkippedHttpsPromotionCount);
        Assert.Equal(2, result.HttpsEndpointCount);
        Assert.Equal(2, result.EntryCount);
        Assert.Equal(2, result.TargetOriginCounts["ct-discovery"]);
        Assert.Equal(2, result.CaptureDispositionCounts["live-probe"]);
        Assert.Contains(result.Snapshot.Entries, entry => entry.Host.Equals("portal.example.com", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(result.Snapshot.Entries, entry => entry.Host.Equals("api.example.com", StringComparison.OrdinalIgnoreCase));
        Assert.All(result.Snapshot.Entries, entry => {
            Assert.Contains("ct-discovery", entry.TargetOrigins, StringComparer.OrdinalIgnoreCase);
            Assert.Equal("live-probe", entry.CaptureDisposition);
        });
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
        Assert.Equal(4, result.HttpsTargetCountBeforeLimit);
        Assert.Equal(0, result.MailTargetCountBeforeLimit);
        Assert.Equal(2, result.HttpsTargetCountDroppedByLimit);
        Assert.Equal(0, result.MailTargetCountDroppedByLimit);
        Assert.Equal(2, result.TargetDecisionDiagnostics.Count);
        Assert.All(result.TargetDecisionDiagnostics, diagnostic => {
            Assert.Equal("target-limit", diagnostic.Stage);
            Assert.Equal("pruned", diagnostic.Action);
            Assert.Equal("max-targets", diagnostic.Reason);
            Assert.Equal("informational", diagnostic.Severity);
            Assert.Equal("Increase MaxTargets or narrow discovery scope if the omitted targets should be probed.", diagnostic.RecommendedAction);
            Assert.Equal("HTTPS", diagnostic.Service);
            Assert.NotNull(diagnostic.PriorityScore);
        });
        Assert.All(result.TargetDecisionDiagnostics, diagnostic =>
            Assert.DoesNotContain(result.HttpsEndpoints, endpoint => string.Equals(endpoint, diagnostic.Target, StringComparison.OrdinalIgnoreCase)));
        var maxTargetSummary = Assert.Single(result.TargetDecisionSummary);
        Assert.Equal("target-limit", maxTargetSummary.Stage);
        Assert.Equal("pruned", maxTargetSummary.Action);
        Assert.Equal("max-targets", maxTargetSummary.Reason);
        Assert.Equal("informational", maxTargetSummary.Severity);
        Assert.Equal("Increase MaxTargets or narrow discovery scope if the omitted targets should be probed.", maxTargetSummary.RecommendedAction);
        Assert.Equal(2, maxTargetSummary.Count);
        Assert.Contains("HTTPS", maxTargetSummary.ExampleServices, StringComparer.OrdinalIgnoreCase);
        Assert.All(maxTargetSummary.ExampleTargets, target =>
            Assert.DoesNotContain(result.HttpsEndpoints, endpoint => string.Equals(endpoint, target, StringComparison.OrdinalIgnoreCase)));
        Assert.Contains(result.Warnings, warning => warning.Contains("capped", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ComputeNativeSharedMaxRows_UsesConfiguredAggregateLimitInsteadOfHardcodedClamp() {
        int effective = CertificateInventoryCapture.ComputeNativeSharedMaxRows(
            domainCount: 25,
            maxCtRowsPerDomain: 150_000,
            nativeCtSharedMaxRowsTotal: 3_000_000);

        Assert.Equal(3_000_000, effective);
    }

    [Fact]
    public void ComputeNativeSharedMaxSubdomains_ReturnsComputedValueWhenBelowConfiguredCeiling() {
        int effective = CertificateInventoryCapture.ComputeNativeSharedMaxSubdomains(
            domainCount: 300,
            maxCtSubdomainsPerDomain: 5_000,
            nativeCtSharedMaxSubdomainsTotal: 2_000_000);

        Assert.Equal(1_500_000, effective);
    }

    [Fact]
    public void ComputeNativeSharedMaxSubdomains_UsesConfiguredAggregateLimitWhenComputedValueExceedsCeiling() {
        int effective = CertificateInventoryCapture.ComputeNativeSharedMaxSubdomains(
            domainCount: 1_000,
            maxCtSubdomainsPerDomain: 5_000,
            nativeCtSharedMaxSubdomainsTotal: 2_000_000);

        Assert.Equal(2_000_000, effective);
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
    public async Task CaptureAsync_AppliesMaxTargetsLimit_AfterReusableStableFailuresAreFiltered() {
        var cacheDirectory = Path.Combine(Path.GetTempPath(), "dd-ci-limit-reuse-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(cacheDirectory);
        try {
            var snapshot = new CertificateInventorySnapshot {
                CapturedAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10),
                Port = 443
            };
            snapshot.Entries.Add(new CertificateInventoryEntry {
                Host = "cached.example.com",
                ResolvedHost = "cached.example.com",
                Url = "https://cached.example.com/",
                Scheme = "https",
                Port = 443,
                Service = "HTTPS",
                CertificateThumbprint = null,
                IsReachable = false,
                Valid = false,
                Expired = false,
                FailureReason = "TLS Handshake Failure",
                TargetOrigins = new[] { "seed-apex" }
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
                ReuseRecentSnapshotEntries = false,
                ReuseRecentFailureSnapshotEntries = true,
                RecentFailureSnapshotTtl = TimeSpan.FromHours(1),
                MaxTargets = 1,
                PersistSnapshot = false
            };
            options.AdditionalEndpoints.Add("https://cached.example.com");
            options.AdditionalEndpoints.Add("https://fresh.example.com");

            var result = await capture.CaptureAsync(new[] { "example.com" }, options, cancellationToken: CancellationToken.None);

            Assert.Single(observedHttpsTargets);
            Assert.Contains(observedHttpsTargets, target => target.Contains("fresh.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.DoesNotContain(observedHttpsTargets, target => target.Contains("cached.example.com", StringComparison.OrdinalIgnoreCase));
            Assert.Equal(1, result.ReusedRecentFailureEntryCount);
            Assert.Equal(1, result.ReusedRecentFailureHttpsCount);
            Assert.Equal(1, result.ProbedHttpsCount);
            Assert.Equal(2, result.EntryCount);
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
                NotAfterUtc = DateTimeOffset.UtcNow.AddDays(120),
                TargetOrigins = new[] { "seed-apex" }
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
            Assert.Equal(1, result.ReusedRecentEntryCount);
            Assert.Equal(1, result.ReusedRecentHttpsCount);
            Assert.Equal(0, result.ReusedRecentMailCount);
            Assert.Equal(0, result.ReusedRecentFailureEntryCount);
            Assert.Equal(0, result.ProbedHttpsCount);
            Assert.Equal(0, result.ProbedMailCount);
            Assert.Contains(result.Snapshot.Entries, entry =>
                entry.Host.Equals("api.example.com", StringComparison.OrdinalIgnoreCase) &&
                entry.TargetOrigins.Contains("additional-endpoint", StringComparer.OrdinalIgnoreCase) &&
                !entry.TargetOrigins.Contains("seed-apex", StringComparer.OrdinalIgnoreCase) &&
                entry.CaptureDisposition == "reused-recent-success");
        } finally {
            try {
                Directory.Delete(cacheDirectory, true);
            } catch {
                // no-op
            }
        }
    }

    [Fact]
    public async Task CaptureAsync_PrefersHttpsOverMail_WhenOnlyOneTargetIsAllowed() {
        using var certificate = CreateSelfSignedWithEku(CertificateExtendedKeyUsageAnalyzer.ServerAuthenticationOid);
        var observedHttpsTargets = new List<string>();
        var capture = new CertificateInventoryCapture {
            MxLookupOverride = (domain, dnsConfiguration, maxMxHostsPerDomain, cancellationToken) =>
                Task.FromResult<IReadOnlyList<string>>(new[] { "mx.invalid" }),
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
            IncludeApexHttps = true,
            IncludeWwwHttps = false,
            IncludeMxHosts = true,
            IncludeMxHttps = false,
            IncludeSmtpStartTls = true,
            IncludeSubmissionStartTls = false,
            IncludeImapTls = false,
            IncludePop3Tls = false,
            MaxTargets = 1,
            PersistSnapshot = false
        };

        var result = await capture.CaptureAsync(new[] { "example.com" }, options, cancellationToken: CancellationToken.None);

        Assert.Single(observedHttpsTargets);
        Assert.Contains(observedHttpsTargets, target => target.Contains("example.com", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(1, result.HttpsEndpointCount);
        Assert.Equal(0, result.MailEndpointCount);
        Assert.Equal(1, result.HttpsTargetCountBeforeLimit);
        Assert.Equal(1, result.MailTargetCountBeforeLimit);
        Assert.Equal(0, result.HttpsTargetCountDroppedByLimit);
        Assert.Equal(1, result.MailTargetCountDroppedByLimit);
    }

    [Fact]
    public async Task CaptureAsync_ReusesRecentStableFailureSnapshotEntries_WhenEnabled() {
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
                CertificateThumbprint = null,
                IsReachable = false,
                Valid = false,
                Expired = false,
                FailureReason = "The operation timed out. | SocketError:TimedOut | FailureKind:Timeout"
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
                ReuseRecentSnapshotEntries = false,
                ReuseRecentFailureSnapshotEntries = true,
                RecentFailureSnapshotTtl = TimeSpan.FromHours(1),
                PersistSnapshot = false
            };
            options.AdditionalEndpoints.Add("https://api.example.com");

            var result = await capture.CaptureAsync(new[] { "example.com" }, options, cancellationToken: CancellationToken.None);

            Assert.Equal(0, observedHttpsTargets);
            Assert.Equal(1, result.EntryCount);
            Assert.Equal(1, result.FailedCount);
            Assert.Equal(1, result.ReusedRecentEntryCount);
            Assert.Equal(1, result.ReusedRecentHttpsCount);
            Assert.Equal(0, result.ReusedRecentMailCount);
            Assert.Equal(1, result.ReusedRecentFailureEntryCount);
            Assert.Equal(1, result.ReusedRecentFailureHttpsCount);
            Assert.Equal(0, result.ReusedRecentFailureMailCount);
            Assert.Equal(0, result.ProbedHttpsCount);
            Assert.Equal(0, result.ProbedMailCount);
            Assert.Contains(result.Snapshot.Entries, entry =>
                entry.Host.Equals("api.example.com", StringComparison.OrdinalIgnoreCase) &&
                entry.TargetOrigins.Contains("additional-endpoint", StringComparer.OrdinalIgnoreCase) &&
                entry.CaptureDisposition == "reused-recent-stable-failure");
        } finally {
            try {
                Directory.Delete(cacheDirectory, true);
            } catch {
                // no-op
            }
        }
    }

    [Fact]
    public async Task CaptureAsync_ReusesRecentTlsHandshakeFailureSnapshotEntries_WhenEnabled() {
        var cacheDirectory = Path.Combine(Path.GetTempPath(), "dd-ci-cache-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(cacheDirectory);
        try {
            var snapshot = new CertificateInventorySnapshot {
                CapturedAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10),
                Port = 443
            };
            snapshot.Entries.Add(new CertificateInventoryEntry {
                Host = "handshake.example.com",
                ResolvedHost = "handshake.example.com",
                Url = "https://handshake.example.com/",
                Scheme = "https",
                Port = 443,
                Service = "HTTPS",
                CertificateThumbprint = null,
                IsReachable = false,
                Valid = false,
                Expired = false,
                FailureReason = "TLS Handshake Failure"
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
                ReuseRecentSnapshotEntries = false,
                ReuseRecentFailureSnapshotEntries = true,
                RecentFailureSnapshotTtl = TimeSpan.FromHours(1),
                PersistSnapshot = false
            };
            options.AdditionalEndpoints.Add("https://handshake.example.com");

            var result = await capture.CaptureAsync(new[] { "example.com" }, options, cancellationToken: CancellationToken.None);

            Assert.Equal(0, observedHttpsTargets);
            Assert.Equal(1, result.EntryCount);
            Assert.Equal(1, result.FailedCount);
            Assert.Equal(1, result.ReusedRecentEntryCount);
            Assert.Equal(1, result.ReusedRecentHttpsCount);
            Assert.Equal(1, result.ReusedRecentFailureEntryCount);
            Assert.Equal(1, result.ReusedRecentFailureHttpsCount);
            Assert.Equal(0, result.ProbedHttpsCount);
            Assert.Contains(result.Snapshot.Entries, entry => entry.Host.Equals("handshake.example.com", StringComparison.OrdinalIgnoreCase));
        } finally {
            try {
                Directory.Delete(cacheDirectory, true);
            } catch {
                // no-op
            }
        }
    }

    [Fact]
    public async Task CaptureAsync_ReusesReachableTlsHandshakeFailureSnapshotEntries_WhenEnabled() {
        var cacheDirectory = Path.Combine(Path.GetTempPath(), "dd-ci-cache-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(cacheDirectory);
        try {
            var snapshot = new CertificateInventorySnapshot {
                CapturedAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10),
                Port = 443
            };
            snapshot.Entries.Add(new CertificateInventoryEntry {
                Host = "reachable-handshake.example.com",
                ResolvedHost = "reachable-handshake.example.com",
                Url = "https://reachable-handshake.example.com/",
                Scheme = "https",
                Port = 443,
                Service = "HTTPS",
                CertificateThumbprint = null,
                IsReachable = true,
                Valid = false,
                Expired = false,
                FailureReason = "TLS Handshake Failure"
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
                ReuseRecentSnapshotEntries = false,
                ReuseRecentFailureSnapshotEntries = true,
                RecentFailureSnapshotTtl = TimeSpan.FromHours(1),
                PersistSnapshot = false
            };
            options.AdditionalEndpoints.Add("https://reachable-handshake.example.com");

            var result = await capture.CaptureAsync(new[] { "example.com" }, options, cancellationToken: CancellationToken.None);

            Assert.Equal(0, observedHttpsTargets);
            Assert.Equal(1, result.ReusedRecentEntryCount);
            Assert.Equal(1, result.ReusedRecentFailureEntryCount);
            Assert.Equal(1, result.ReusedRecentFailureHttpsCount);
            Assert.Equal(0, result.ProbedHttpsCount);
            Assert.Contains(result.Snapshot.Entries, entry => entry.Host.Equals("reachable-handshake.example.com", StringComparison.OrdinalIgnoreCase));
        } finally {
            try {
                Directory.Delete(cacheDirectory, true);
            } catch {
                // no-op
            }
        }
    }

    [Fact]
    public async Task CaptureAsync_ReusesRecentHttpRequestNameResolutionSnapshotEntries_WhenEnabled() {
        var cacheDirectory = Path.Combine(Path.GetTempPath(), "dd-ci-cache-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(cacheDirectory);
        try {
            var snapshot = new CertificateInventorySnapshot {
                CapturedAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10),
                Port = 443
            };
            snapshot.Entries.Add(new CertificateInventoryEntry {
                Host = "missing.example.com",
                ResolvedHost = "missing.example.com",
                Url = "https://missing.example.com/",
                Scheme = "https",
                Port = 443,
                Service = "HTTPS",
                CertificateThumbprint = null,
                IsReachable = false,
                Valid = false,
                Expired = false,
                FailureReason = "Name resolution failed. | HttpRequestError:NameResolutionError"
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
                ReuseRecentSnapshotEntries = false,
                ReuseRecentFailureSnapshotEntries = true,
                RecentFailureSnapshotTtl = TimeSpan.FromHours(1),
                PersistSnapshot = false
            };
            options.AdditionalEndpoints.Add("https://missing.example.com");

            var result = await capture.CaptureAsync(new[] { "example.com" }, options, cancellationToken: CancellationToken.None);

            Assert.Equal(0, observedHttpsTargets);
            Assert.Equal(1, result.EntryCount);
            Assert.Equal(1, result.FailedCount);
            Assert.Equal(1, result.ReusedRecentEntryCount);
            Assert.Equal(1, result.ReusedRecentHttpsCount);
            Assert.Equal(1, result.ReusedRecentFailureEntryCount);
            Assert.Equal(1, result.ReusedRecentFailureHttpsCount);
            Assert.Equal(0, result.ProbedHttpsCount);
            Assert.Contains(result.Snapshot.Entries, entry => entry.Host.Equals("missing.example.com", StringComparison.OrdinalIgnoreCase));
        } finally {
            try {
                Directory.Delete(cacheDirectory, true);
            } catch {
                // no-op
            }
        }
    }

    [Fact]
    public async Task CaptureAsync_ReusesRecentStructuredFailureSnapshotEntries_WhenReasonIsNonStandard() {
        var cacheDirectory = Path.Combine(Path.GetTempPath(), "dd-ci-cache-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(cacheDirectory);
        try {
            var snapshot = new CertificateInventorySnapshot {
                CapturedAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10),
                Port = 443
            };
            snapshot.Entries.Add(new CertificateInventoryEntry {
                Host = "structured.example.com",
                ResolvedHost = "structured.example.com",
                Url = "https://structured.example.com/",
                Scheme = "https",
                Port = 443,
                Service = "HTTPS",
                CertificateThumbprint = null,
                IsReachable = false,
                Valid = false,
                Expired = false,
                FailureReason = "Transient edge transport issue",
                FailureKind = CertificateFailureKind.NameResolution
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
                ReuseRecentSnapshotEntries = false,
                ReuseRecentFailureSnapshotEntries = true,
                RecentFailureSnapshotTtl = TimeSpan.FromHours(1),
                PersistSnapshot = false
            };
            options.AdditionalEndpoints.Add("https://structured.example.com");

            var result = await capture.CaptureAsync(new[] { "example.com" }, options, cancellationToken: CancellationToken.None);

            Assert.Equal(0, observedHttpsTargets);
            Assert.Equal(1, result.EntryCount);
            Assert.Equal(1, result.FailedCount);
            Assert.Equal(1, result.ReusedRecentEntryCount);
            Assert.Equal(1, result.ReusedRecentHttpsCount);
            Assert.Equal(1, result.ReusedRecentFailureEntryCount);
            Assert.Equal(1, result.ReusedRecentFailureHttpsCount);
            Assert.Equal(0, result.ProbedHttpsCount);
            Assert.Contains(result.Snapshot.Entries, entry => entry.Host.Equals("structured.example.com", StringComparison.OrdinalIgnoreCase));
        } finally {
            try {
                Directory.Delete(cacheDirectory, true);
            } catch {
                // no-op
            }
        }
    }

    [Fact]
    public async Task CaptureAsync_DoesNotReuseRecentStableFailureSnapshotEntries_WhenBeyondFailureTtl() {
        var cacheDirectory = Path.Combine(Path.GetTempPath(), "dd-ci-cache-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(cacheDirectory);
        try {
            var snapshot = new CertificateInventorySnapshot {
                CapturedAtUtc = DateTimeOffset.UtcNow.AddHours(-2),
                Port = 443
            };
            snapshot.Entries.Add(new CertificateInventoryEntry {
                Host = "api.example.com",
                ResolvedHost = "api.example.com",
                Url = "https://api.example.com/",
                Scheme = "https",
                Port = 443,
                Service = "HTTPS",
                CertificateThumbprint = null,
                IsReachable = false,
                Valid = false,
                Expired = false,
                FailureReason = "No such host is known. | SocketError:HostNotFound"
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
                ReuseRecentSnapshotEntries = false,
                ReuseRecentFailureSnapshotEntries = true,
                RecentFailureSnapshotTtl = TimeSpan.FromMinutes(30),
                PersistSnapshot = false
            };
            options.AdditionalEndpoints.Add("https://api.example.com");

            var result = await capture.CaptureAsync(new[] { "example.com" }, options, cancellationToken: CancellationToken.None);

            Assert.Equal(0, result.ReusedRecentEntryCount);
            Assert.Equal(0, result.ReusedRecentFailureEntryCount);
            Assert.Equal(1, result.ProbedHttpsCount);
            Assert.Equal(0, result.ProbedMailCount);
            Assert.Equal(1, observedHttpsTargets);
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
        Assert.Equal(4, result.MxInvalidArtifactCount);
        Assert.Equal(0, result.MxDuplicateHostCount);
        Assert.Equal(2, result.MxPromotedHttpsCount);
        Assert.Equal(0, result.MxPromotedMailCount);
        Assert.Equal(0, result.MxSkippedDuplicateHttpsPromotionCount);
        Assert.Equal(2, result.HttpsEndpointCount);
        Assert.DoesNotContain(result.MxHosts, host => host.Equals("0", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(result.MxHosts, host => host.Equals("mx1.example.com", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(result.MxHosts, host => host.Equals("mx2.example.com", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task CaptureAsync_CountsMxHostsThatCollapseIntoExistingHttpsTargets() {
        using var certificate = CreateSelfSignedWithEku(CertificateExtendedKeyUsageAnalyzer.ServerAuthenticationOid);
        var capture = new CertificateInventoryCapture {
            MxLookupOverride = (domain, dnsConfiguration, maxMxHostsPerDomain, cancellationToken) => {
                IReadOnlyList<string> hosts = new[] { "mx1.example.com" };
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

        var result = await capture.CaptureAsync(new[] { "example.com", "mx1.example.com" }, options, cancellationToken: CancellationToken.None);

        Assert.Equal(1, result.MxHostCount);
        Assert.Equal(0, result.MxPromotedHttpsCount);
        Assert.Equal(1, result.MxSkippedDuplicateHttpsPromotionCount);
        Assert.Equal(1, result.HttpsEndpointCount);
        Assert.Contains(result.HttpsEndpoints, endpoint => endpoint.Contains("mx1.example.com", StringComparison.OrdinalIgnoreCase));
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
    public void ConfigureHttpsAnalysis_DisablesExtendedHttpsMetadataWhenRequested() {
        var analysis = new CertificateAnalysis();
        var options = new CertificateInventoryCaptureOptions {
            CaptureExtendedHttpsMetadata = false,
            PreferTlsHandshakeOnlyProbe = true,
            SkipRevocation = false
        };

        CertificateInventoryCapture.ConfigureHttpsAnalysis(analysis, options);

        Assert.False(analysis.CaptureTlsDetails);
        Assert.False(analysis.CaptureExtendedMetadata);
        Assert.False(analysis.CaptureCtMetadata);
        Assert.True(analysis.PreferTlsHandshakeOnlyProbe);
        Assert.True(analysis.ShouldUseTlsHandshakeOnlyProbe());
        Assert.True(analysis.SkipRevocation);
    }

    [Fact]
    public void ConfigureHttpsAnalysis_AllowsTargetedCtMetadataWhenExtendedMetadataIsDisabled() {
        var analysis = new CertificateAnalysis();
        var options = new CertificateInventoryCaptureOptions {
            CaptureExtendedHttpsMetadata = false,
            CtProfile = CertificateCtEnrichmentProfile.Public,
            EnablePassiveCtFallback = false,
            EnablePassiveCtMetadataFallback = true,
            IncludeDefaultCtTemplate = true
        };
        options.CtMetadataTargetHosts.Add("www.example.com");

        CertificateInventoryCapture.ConfigureHttpsAnalysis(analysis, options, "https://www.example.com");

        Assert.False(analysis.CaptureTlsDetails);
        Assert.False(analysis.CaptureExtendedMetadata);
        Assert.True(analysis.CaptureCtMetadata);
        Assert.True(analysis.SkipRevocation);
        Assert.Contains("https://crt.sh/?sha256={0}&output=json", analysis.CtLogApiTemplates);
    }

    [Fact]
    public async Task CaptureAsync_HydratesUnreachableCtEndpointWithCtCertificateMetadata() {
        var ctFirstSeen = new DateTimeOffset(2024, 1, 5, 10, 0, 0, TimeSpan.Zero);
        var ctLastSeen = new DateTimeOffset(2026, 2, 10, 12, 0, 0, TimeSpan.Zero);
        var ctNotBefore = new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var ctNotAfter = new DateTimeOffset(2026, 10, 1, 23, 59, 59, TimeSpan.Zero);
        var capture = new CertificateInventoryCapture {
            EndpointDnsQueryOverride = (_, _, _) => Task.FromResult(Array.Empty<DnsAnswer>()),
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
            BackfillMissingCtCertificateMetadata = false,
            IncludeMxHosts = false,
            IncludeMxHttps = false,
            IncludeSmtpStartTls = false,
            IncludeSubmissionStartTls = false,
            IncludeImapTls = false,
            IncludePop3Tls = false,
            EnableEndpointAttribution = true,
            PersistSnapshot = false
        };
        var issuerRule = new EndpointAttributionRule {
            RuleId = "custom.ct-issuer",
            RuleVersion = "1",
            ProviderId = "example",
            ServiceId = "ct-backed",
            DisplayName = "CT-backed endpoint",
            MinimumScore = 0.15,
            AllowWeakSignalsAsPrimary = true
        };
        issuerRule.CertificateIssuerContains.Add("Test Issuer");
        options.EndpointAttributionRules.Add(issuerRule);

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
        EndpointAttributionCandidate issuerCandidate = Assert.Single(
            endpoint.Attribution!.Candidates,
            candidate => candidate.RuleId == "custom.ct-issuer");
        Assert.Contains(
            issuerCandidate.Evidence,
            evidence => evidence.Kind == EndpointAttributionSignalKind.CertificateIssuer &&
                        evidence.ObservedValue.Contains("Test Issuer", StringComparison.Ordinal));

        var discovered = Assert.Single(result.CtDiscoveredSubdomainEntries);
        Assert.Equal("ct-only.example.com", discovered.Name);
        Assert.Equal(ctLastSeen, discovered.LatestCertificateCtEntryTimestampUtc);
        Assert.Equal("CN=ct-only.example.com", discovered.LatestCertificateSubject);
    }

    [Fact]
    public async Task CaptureAsync_DoesNotProbeUnresolvedCtDiscoveredHostsWhenVerificationIsEnabled() {
        var probedHosts = new List<string>();
        var capture = new CertificateInventoryCapture {
            CtSubdomainEntryDiscoveryOverride = (domains, options, logger, cancellationToken) => {
                IReadOnlyList<SubdomainDiscoveryEntry> discovered = new[] {
                    new SubdomainDiscoveryEntry {
                        Name = "resolved.example.com",
                        ResolutionStatus = SubdomainResolutionStatus.Resolves,
                        CtSources = new[] { "native-ct" }
                    },
                    new SubdomainDiscoveryEntry {
                        Name = "unresolved.example.com",
                        ResolutionStatus = SubdomainResolutionStatus.DoesNotResolve,
                        CtSources = new[] { "native-ct" }
                    },
                    new SubdomainDiscoveryEntry {
                        Name = "unverified-overflow.example.com",
                        ResolutionStatus = SubdomainResolutionStatus.Unknown,
                        CtSources = new[] { "native-ct" }
                    }
                };
                return Task.FromResult(discovered);
            },
            HttpsProbeOverride = (httpsTargets, options, logger, cancellationToken) => {
                foreach (string target in httpsTargets) {
                    probedHosts.Add(new Uri(target).Host);
                }

                return Task.FromResult<IReadOnlyList<CertificateMonitor.Entry>>(Array.Empty<CertificateMonitor.Entry>());
            }
        };

        var options = new CertificateInventoryCaptureOptions {
            IncludeApexHttps = false,
            IncludeWwwHttps = false,
            IncludeCtDiscoveredSubdomains = true,
            VerifyCtDiscoveredSubdomains = true,
            EnablePassiveCtFallback = false,
            IncludeMxHosts = false,
            IncludeMxHttps = false,
            IncludeSmtpStartTls = false,
            IncludeSubmissionStartTls = false,
            IncludeImapTls = false,
            IncludePop3Tls = false,
            PersistSnapshot = false
        };

        var result = await capture.CaptureAsync(new[] { "example.com" }, options, cancellationToken: CancellationToken.None);

        Assert.Contains("resolved.example.com", probedHosts, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("unresolved.example.com", probedHosts, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("unverified-overflow.example.com", probedHosts, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(3, result.CtDiscoveredSubdomainCount);
        Assert.Equal(1, result.CtPromotedHttpsCount);
        Assert.Equal(2, result.CtSkippedHttpsPromotionCount);
        Assert.Equal(2, result.CtSkippedUnresolvedHttpsPromotionCount);
        Assert.Equal(0, result.CtSkippedLowConfidenceHttpsPromotionCount);
        Assert.Equal(0, result.CtSkippedDuplicateHttpsPromotionCount);
    }

    [Fact]
    public async Task CaptureAsync_PreservesLowConfidenceCtHostsButSkipsUnknownWVariantsFromHttpsProbes() {
        var verboseMessages = new List<string>();
        var probedHosts = new List<string>();
        var capture = new CertificateInventoryCapture {
            CtSubdomainEntryDiscoveryOverride = (domains, options, logger, cancellationToken) => {
                IReadOnlyList<SubdomainDiscoveryEntry> discovered = new[] {
                    new SubdomainDiscoveryEntry {
                        Name = "w.example.com",
                        ResolutionStatus = SubdomainResolutionStatus.Unknown,
                        CtSources = new[] { "crt.sh" }
                    },
                    new SubdomainDiscoveryEntry {
                        Name = "ww.example.com",
                        ResolutionStatus = SubdomainResolutionStatus.Unknown,
                        CtSources = new[] { "crt.sh" }
                    },
                    new SubdomainDiscoveryEntry {
                        Name = "www.example.com",
                        ResolutionStatus = SubdomainResolutionStatus.Unknown,
                        CtSources = new[] { "crt.sh" }
                    },
                    new SubdomainDiscoveryEntry {
                        Name = "wwww.example.com",
                        ResolutionStatus = SubdomainResolutionStatus.Unknown,
                        CtSources = new[] { "crt.sh" }
                    },
                    new SubdomainDiscoveryEntry {
                        Name = "api.example.com",
                        ResolutionStatus = SubdomainResolutionStatus.Unknown,
                        CtSources = new[] { "crt.sh" }
                    }
                };
                return Task.FromResult(discovered);
            },
            HttpsProbeOverride = (httpsTargets, options, logger, cancellationToken) => {
                foreach (string target in httpsTargets) {
                    probedHosts.Add(new Uri(target).Host);
                }

                return Task.FromResult<IReadOnlyList<CertificateMonitor.Entry>>(Array.Empty<CertificateMonitor.Entry>());
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
            PersistSnapshot = false
        };

        var logger = new InternalLogger(false);
        logger.OnVerboseMessage += (_, args) => {
            if (!string.IsNullOrWhiteSpace(args.Message)) {
                verboseMessages.Add(args.Message);
            }
        };

        var result = await capture.CaptureAsync(new[] { "example.com" }, options, logger, CancellationToken.None);

        Assert.Equal(5, result.CtDiscoveredSubdomainCount);
        Assert.Equal(2, result.CtPromotedHttpsCount);
        Assert.Equal(3, result.CtSkippedHttpsPromotionCount);
        Assert.Equal(0, result.CtSkippedUnresolvedHttpsPromotionCount);
        Assert.Equal(3, result.CtSkippedLowConfidenceHttpsPromotionCount);
        Assert.Equal(0, result.CtSkippedDuplicateHttpsPromotionCount);
        Assert.Contains("www.example.com", probedHosts, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("api.example.com", probedHosts, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("w.example.com", probedHosts, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("ww.example.com", probedHosts, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("wwww.example.com", probedHosts, StringComparer.OrdinalIgnoreCase);
        Assert.Contains(
            verboseMessages,
            message => message.Contains("low-confidence historical-only candidate", StringComparison.OrdinalIgnoreCase));
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
        PassiveCtSourceClient.ResetSharedStateForTesting();
        try {
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
        } finally {
            PassiveCtSourceClient.ResetSharedStateForTesting();
        }
    }

    [Fact]
    public void MergeCtSubdomainEntry_PrefersCoherentLatestCertificateBundleAcrossDifferentCertificates() {
        const string hostName = "mixed-bundle.example.com";
        var existing = new SubdomainDiscoveryEntry {
            Name = hostName,
            LatestCertificateCtEntryTimestampUtc = new DateTimeOffset(2026, 3, 1, 8, 0, 0, TimeSpan.Zero),
            LatestCertificateSubject = "CN=legacy.example.com",
            LatestCertificateIssuer = "CN=Legacy Issuer",
            LatestCertificateSerialNumber = "LEGACY-SERIAL",
            LatestCertificateNotBeforeUtc = new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero),
            LatestCertificateNotAfterUtc = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero)
        };
        var candidate = new SubdomainDiscoveryEntry {
            Name = hostName,
            LatestCertificateCtEntryTimestampUtc = new DateTimeOffset(2026, 3, 2, 8, 0, 0, TimeSpan.Zero),
            LatestCertificateThumbprint = "AABBCCDDEEFF00112233445566778899AABBCCDD",
            LatestCertificateSubject = "CN=current.example.com",
            LatestCertificateIssuer = "CN=Current Issuer",
            LatestCertificateNotBeforeUtc = new DateTimeOffset(2026, 2, 1, 0, 0, 0, TimeSpan.Zero),
            LatestCertificateNotAfterUtc = new DateTimeOffset(2027, 2, 1, 0, 0, 0, TimeSpan.Zero)
        };
        IDictionary<string, SubdomainDiscoveryEntry> byName = new Dictionary<string, SubdomainDiscoveryEntry>(StringComparer.OrdinalIgnoreCase) {
            [hostName] = existing
        };

        MethodInfo? method = typeof(CertificateInventoryCapture).GetMethod(
            "MergeCtSubdomainEntry",
            BindingFlags.Static | BindingFlags.NonPublic);
        Assert.NotNull(method);

        _ = method!.Invoke(null, new object[] { byName, candidate });

        SubdomainDiscoveryEntry merged = byName[hostName];
        Assert.Equal(candidate.LatestCertificateThumbprint, merged.LatestCertificateThumbprint);
        Assert.Equal(candidate.LatestCertificateSubject, merged.LatestCertificateSubject);
        Assert.Equal(candidate.LatestCertificateIssuer, merged.LatestCertificateIssuer);
        Assert.Null(merged.LatestCertificateSerialNumber);
        Assert.Equal(candidate.LatestCertificateNotBeforeUtc, merged.LatestCertificateNotBeforeUtc);
        Assert.Equal(candidate.LatestCertificateNotAfterUtc, merged.LatestCertificateNotAfterUtc);
    }

    [Fact]
    public void MergeCtSubdomainEntry_MergesMissingFieldsWhenBothCandidatesDescribeSameCertificate() {
        const string hostName = "same-certificate.example.com";
        var existing = new SubdomainDiscoveryEntry {
            Name = hostName,
            LatestCertificateCtEntryTimestampUtc = new DateTimeOffset(2026, 3, 1, 8, 0, 0, TimeSpan.Zero),
            LatestCertificateSubject = "CN=same-certificate.example.com",
            LatestCertificateIssuer = "CN=Shared Issuer",
            LatestCertificateSerialNumber = "SHARED-SERIAL",
            LatestCertificateNotBeforeUtc = new DateTimeOffset(2026, 2, 1, 0, 0, 0, TimeSpan.Zero),
            LatestCertificateNotAfterUtc = new DateTimeOffset(2027, 2, 1, 0, 0, 0, TimeSpan.Zero),
            LatestCertificateAuthenticationProfile = "ServerAuth"
        };
        var candidate = new SubdomainDiscoveryEntry {
            Name = hostName,
            LatestCertificateCtEntryTimestampUtc = new DateTimeOffset(2026, 3, 2, 8, 0, 0, TimeSpan.Zero),
            LatestCertificateThumbprint = "FFEEDDCCBBAA99887766554433221100FFEEDDCC",
            LatestCertificateSubject = "CN=same-certificate.example.com",
            LatestCertificateIssuer = "CN=Shared Issuer",
            LatestCertificateSerialNumber = "SHARED-SERIAL",
            LatestCertificateNotBeforeUtc = new DateTimeOffset(2026, 2, 1, 0, 0, 0, TimeSpan.Zero),
            LatestCertificateNotAfterUtc = new DateTimeOffset(2027, 2, 1, 0, 0, 0, TimeSpan.Zero)
        };
        IDictionary<string, SubdomainDiscoveryEntry> byName = new Dictionary<string, SubdomainDiscoveryEntry>(StringComparer.OrdinalIgnoreCase) {
            [hostName] = existing
        };

        MethodInfo? method = typeof(CertificateInventoryCapture).GetMethod(
            "MergeCtSubdomainEntry",
            BindingFlags.Static | BindingFlags.NonPublic);
        Assert.NotNull(method);

        _ = method!.Invoke(null, new object[] { byName, candidate });

        SubdomainDiscoveryEntry merged = byName[hostName];
        Assert.Equal(candidate.LatestCertificateThumbprint, merged.LatestCertificateThumbprint);
        Assert.Equal(existing.LatestCertificateSerialNumber, merged.LatestCertificateSerialNumber);
        Assert.Equal(existing.LatestCertificateAuthenticationProfile, merged.LatestCertificateAuthenticationProfile);
        Assert.Equal(candidate.LatestCertificateSubject, merged.LatestCertificateSubject);
        Assert.Equal(candidate.LatestCertificateIssuer, merged.LatestCertificateIssuer);
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
    public async Task TryHydrateExactCtMetadataThumbprintFromCrtShCertificateAsync_ComputesThumbprintFromDownloadedCertificate() {
        const string hostName = "mail.emmasguesthouse.co.za";
        using RSA rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            $"CN={hostName}",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection {
                    new(CertificateExtendedKeyUsageAnalyzer.ServerAuthenticationOid)
                },
                critical: false));
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        using X509Certificate2 certificate = request.CreateSelfSigned(
            new DateTimeOffset(2026, 3, 26, 0, 3, 0, TimeSpan.Zero),
            new DateTimeOffset(2026, 6, 24, 0, 2, 59, TimeSpan.Zero));
        byte[] certificateBytes = certificate.Export(X509ContentType.Cert);

        var entry = new SubdomainDiscoveryEntry {
            Name = hostName,
            LatestCertificateCtEntryTimestampUtc = new DateTimeOffset(2026, 3, 26, 1, 1, 34, TimeSpan.Zero),
            LatestCertificateSubject = hostName,
            LatestCertificateIssuer = "CN=R13",
            LatestCertificateSerialNumber = "061E581C9CE6E0C0BB18ADCCAF1AF9A99742"
        };
        IReadOnlyList<PassiveCtSourceClient.SourcePayload> payloads = new[] {
            new PassiveCtSourceClient.SourcePayload {
                SourceName = "crt.sh",
                Url = "https://crt.sh/?q=mail.emmasguesthouse.co.za&output=json",
                Payload =
                    """
                    [
                      {
                        "issuer_name": "C=US, O=Let's Encrypt, CN=R13",
                        "common_name": "emmasguesthouse.co.za",
                        "name_value": "mail.emmasguesthouse.co.za",
                        "id": 25223287523,
                        "entry_timestamp": "2026-03-26T01:01:34.298",
                        "not_before": "2026-03-26T00:03:00",
                        "not_after": "2026-06-24T00:02:59",
                        "serial_number": "061E581C9CE6E0C0BB18ADCCAF1AF9A99742"
                      }
                    ]
                    """
            }
        };

        SubdomainDiscoveryEntry hydrated = await CertificateInventoryCapture.TryHydrateExactCtMetadataThumbprintFromCrtShCertificateAsync(
            entry,
            payloads,
            (downloadId, cancellationToken) => Task.FromResult<byte[]?>(downloadId == "25223287523" ? certificateBytes : null),
            TimeSpan.FromSeconds(5),
            logger: null,
            cancellationToken: CancellationToken.None);

        Assert.Equal(certificate.Thumbprint, hydrated.LatestCertificateThumbprint);
        Assert.True(hydrated.LatestCertificateHasServerAuthentication);
        Assert.False(hydrated.LatestCertificateHasClientAuthentication);
        Assert.False(hydrated.LatestCertificateHasSecureEmail);
        Assert.Equal(CertificateAuthenticationProfileClassifier.ServerAuthOnly, hydrated.LatestCertificateAuthenticationProfile);
    }

    [Fact]
    public void TryBuildExactCtMetadataEntryFromCrtShPostgreSqlRows_ComputesThumbprintAndUsesDbSource() {
        const string hostName = "mail.emmasguesthouse.co.za";
        using RSA rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            $"CN={hostName}",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        using X509Certificate2 certificate = request.CreateSelfSigned(
            new DateTimeOffset(2026, 3, 26, 0, 3, 0, TimeSpan.Zero),
            new DateTimeOffset(2026, 6, 24, 0, 2, 59, TimeSpan.Zero));
        byte[] certificateBytes = certificate.Export(X509ContentType.Cert);

        SubdomainDiscoveryEntry? entry = CertificateInventoryCapture.TryBuildExactCtMetadataEntryFromCrtShPostgreSqlRows(
            hostName,
            new[] {
                new CertificateInventoryCapture.CrtShPostgreSqlExactMetadataRow {
                    CertificateDer = certificateBytes,
                    EntryTimestampUtc = new DateTimeOffset(2026, 3, 26, 1, 1, 34, TimeSpan.Zero),
                    CommonName = hostName,
                    IssuerName = certificate.Issuer,
                    SerialNumber = certificate.SerialNumber,
                    NotBeforeUtc = new DateTimeOffset(certificate.NotBefore.ToUniversalTime()),
                    NotAfterUtc = new DateTimeOffset(certificate.NotAfter.ToUniversalTime()),
                    CandidateNames = new[] { hostName, "autodiscover.emmasguesthouse.co.za" }
                }
            });

        Assert.NotNull(entry);
        Assert.Equal(certificate.Thumbprint, entry!.LatestCertificateThumbprint);
        Assert.Equal(certificate.Issuer, entry.LatestCertificateIssuer);
        Assert.Contains("crt.sh-db", entry.CtSources, StringComparer.OrdinalIgnoreCase);
        Assert.Contains(hostName, entry.LatestCertificateSubjectAlternativeNames, StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public void TryBuildExactCtMetadataEntryFromCrtShPostgreSqlRows_PrefersTargetThumbprintOverNewerHostCertificate() {
        const string hostName = "mail.emmasguesthouse.co.za";

        using RSA olderKey = RSA.Create(2048);
        var olderRequest = new CertificateRequest(
            $"CN={hostName}",
            olderKey,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        olderRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        olderRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(olderRequest.PublicKey, false));
        using X509Certificate2 olderCertificate = olderRequest.CreateSelfSigned(
            new DateTimeOffset(2026, 3, 20, 0, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2026, 6, 20, 0, 0, 0, TimeSpan.Zero));

        using RSA newerKey = RSA.Create(2048);
        var newerRequest = new CertificateRequest(
            $"CN={hostName}",
            newerKey,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        newerRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        newerRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(newerRequest.PublicKey, false));
        using X509Certificate2 newerCertificate = newerRequest.CreateSelfSigned(
            new DateTimeOffset(2026, 4, 1, 0, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2026, 7, 1, 0, 0, 0, TimeSpan.Zero));

        SubdomainDiscoveryEntry? entry = CertificateInventoryCapture.TryBuildExactCtMetadataEntryFromCrtShPostgreSqlRows(
            hostName,
            new[] {
                new CertificateInventoryCapture.CrtShPostgreSqlExactMetadataRow {
                    CertificateDer = newerCertificate.Export(X509ContentType.Cert),
                    EntryTimestampUtc = new DateTimeOffset(2026, 4, 1, 12, 0, 0, TimeSpan.Zero),
                    CommonName = hostName,
                    IssuerName = newerCertificate.Issuer,
                    SerialNumber = newerCertificate.SerialNumber,
                    NotBeforeUtc = new DateTimeOffset(newerCertificate.NotBefore.ToUniversalTime()),
                    NotAfterUtc = new DateTimeOffset(newerCertificate.NotAfter.ToUniversalTime()),
                    CandidateNames = new[] { hostName }
                },
                new CertificateInventoryCapture.CrtShPostgreSqlExactMetadataRow {
                    CertificateDer = olderCertificate.Export(X509ContentType.Cert),
                    EntryTimestampUtc = new DateTimeOffset(2026, 3, 20, 12, 0, 0, TimeSpan.Zero),
                    CommonName = hostName,
                    IssuerName = olderCertificate.Issuer,
                    SerialNumber = olderCertificate.SerialNumber,
                    NotBeforeUtc = new DateTimeOffset(olderCertificate.NotBefore.ToUniversalTime()),
                    NotAfterUtc = new DateTimeOffset(olderCertificate.NotAfter.ToUniversalTime()),
                    CandidateNames = new[] { hostName }
                }
            },
            new HashSet<string>(StringComparer.OrdinalIgnoreCase) { olderCertificate.Thumbprint });

        Assert.NotNull(entry);
        Assert.Equal(olderCertificate.Thumbprint, entry!.LatestCertificateThumbprint);
        Assert.Equal(olderCertificate.SerialNumber, entry.LatestCertificateSerialNumber);
        Assert.Contains("crt.sh-db", entry.CtSources, StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public void TryBuildExactCtMetadataEntryFromCrtShPostgreSqlRows_AcceptsWildcardSubjectAlternativeNames() {
        const string hostName = "mail.emmasguesthouse.co.za";
        using RSA rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=*.emmasguesthouse.co.za",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        using X509Certificate2 certificate = request.CreateSelfSigned(
            new DateTimeOffset(2026, 3, 26, 0, 3, 0, TimeSpan.Zero),
            new DateTimeOffset(2026, 6, 24, 0, 2, 59, TimeSpan.Zero));
        byte[] certificateBytes = certificate.Export(X509ContentType.Cert);

        SubdomainDiscoveryEntry? entry = CertificateInventoryCapture.TryBuildExactCtMetadataEntryFromCrtShPostgreSqlRows(
            hostName,
            new[] {
                new CertificateInventoryCapture.CrtShPostgreSqlExactMetadataRow {
                    CertificateDer = certificateBytes,
                    EntryTimestampUtc = new DateTimeOffset(2026, 3, 26, 1, 1, 34, TimeSpan.Zero),
                    CommonName = "*.emmasguesthouse.co.za",
                    IssuerName = certificate.Issuer,
                    SerialNumber = certificate.SerialNumber,
                    NotBeforeUtc = new DateTimeOffset(certificate.NotBefore.ToUniversalTime()),
                    NotAfterUtc = new DateTimeOffset(certificate.NotAfter.ToUniversalTime()),
                    CandidateNames = new[] { "*.emmasguesthouse.co.za" }
                }
            });

        Assert.NotNull(entry);
        Assert.Equal(certificate.Thumbprint, entry!.LatestCertificateThumbprint);
        Assert.Contains("crt.sh-db", entry.CtSources, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("*.emmasguesthouse.co.za", entry.LatestCertificateSubjectAlternativeNames, StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public void BuildCrtShPostgreSqlExactMetadataQuery_UsesSupportedFullTextAndAltNamePath() {
        string query = CertificateInventoryCapture.BuildCrtShPostgreSqlExactMetadataQuery();

        Assert.Contains("identities(c.certificate)", query, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("x509_altnames(c.certificate)", query, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("encode(x509_serialNumber(c.certificate), 'hex')", query, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("@wildcardHost", query, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("certificate_identity", query, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void BuildWildcardCandidateHost_DoesNotBroadenRegistrableRootsToTopLevelWildcards() {
        Assert.Equal("abclabs.com", CertificateInventoryCapture.BuildWildcardCandidateHost("abclabs.com"));
        Assert.Equal("eurofins.pl", CertificateInventoryCapture.BuildWildcardCandidateHost("eurofins.pl"));
        Assert.Equal("*.example.com", CertificateInventoryCapture.BuildWildcardCandidateHost("mail.example.com"));
        Assert.Equal("*.emmasguesthouse.co.za", CertificateInventoryCapture.BuildWildcardCandidateHost("mail.emmasguesthouse.co.za"));
    }

    [Fact]
    public void BuildCrtShPostgreSqlDomainMetadataQuery_UsesHostArraysAndWildcardAwareMatching() {
        string query = CertificateInventoryCapture.BuildCrtShPostgreSqlDomainMetadataQuery();

        Assert.Contains("identities(c.certificate)", query, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("candidate_name = ANY(@hosts)", query, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("candidate_name = ANY(@wildcardHosts)", query, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("LIMIT @limit", query, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("certificate_identity", query, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void BuildPassiveCtMetadataSourceRequests_PrefersCertSpotterWildcardAwareExactHostQuery() {
        IReadOnlyList<PassiveCtSourceClient.SourceRequest> requests =
            CertificateInventoryCapture.BuildPassiveCtMetadataSourceRequests("access.tchibo.com");

        Assert.Equal(2, requests.Count);
        Assert.Equal("certspotter", requests[0].SourceName);
        Assert.Contains("domain=access.tchibo.com", requests[0].Url, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("include_subdomains=false", requests[0].Url, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("match_wildcards=true", requests[0].Url, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("expand=issuer", requests[0].Url, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("expand=cert_der", requests[0].Url, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("include_subdomains=true", requests[0].Url, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("crt.sh", requests[1].SourceName);
        Assert.Contains("q=access.tchibo.com", requests[1].Url, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TryBuildExactCtMetadataEntry_HydratesCertSpotterCertificateDer() {
        const string hostName = "mail.emmasguesthouse.co.za";
        using RSA rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            $"CN={hostName}",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection {
                    new(CertificateExtendedKeyUsageAnalyzer.ServerAuthenticationOid)
                },
                critical: false));
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        using X509Certificate2 certificate = request.CreateSelfSigned(
            new DateTimeOffset(2026, 3, 26, 0, 3, 0, TimeSpan.Zero),
            new DateTimeOffset(2026, 6, 24, 0, 2, 59, TimeSpan.Zero));
        string certificateDer = Convert.ToBase64String(certificate.Export(X509ContentType.Cert));

        IReadOnlyList<PassiveCtSourceClient.SourcePayload> payloads = new[] {
            new PassiveCtSourceClient.SourcePayload {
                SourceName = "certspotter",
                Url = "https://api.certspotter.com/v1/issuances?domain=mail.emmasguesthouse.co.za&include_subdomains=false&match_wildcards=true&expand=dns_names&expand=issuer&expand=cert_der",
                Payload =
                    $$"""
                    [
                      {
                        "id": "certspotter-test-id",
                        "dns_names": [ "{{hostName}}" ],
                        "issuer": { "name": "CN=placeholder" },
                        "not_before": "2026-03-26T00:03:00Z",
                        "not_after": "2026-06-24T00:02:59Z",
                        "cert_der": "{{certificateDer}}"
                      }
                    ]
                    """
            }
        };

        SubdomainDiscoveryEntry? entry = CertificateInventoryCapture.TryBuildExactCtMetadataEntry(hostName, payloads);

        Assert.NotNull(entry);
        Assert.Equal(certificate.Thumbprint, entry!.LatestCertificateThumbprint);
        Assert.Equal(certificate.Subject, entry.LatestCertificateSubject);
        Assert.Equal(certificate.Issuer, entry.LatestCertificateIssuer);
        Assert.Equal(certificate.SerialNumber, entry.LatestCertificateSerialNumber);
        Assert.True(entry.LatestCertificateHasServerAuthentication);
        Assert.False(entry.LatestCertificateHasClientAuthentication);
        Assert.False(entry.LatestCertificateHasSecureEmail);
        Assert.Equal(CertificateAuthenticationProfileClassifier.ServerAuthOnly, entry.LatestCertificateAuthenticationProfile);
        Assert.Contains("certspotter", entry.CtSources, StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task TryHydrateExactCtMetadataThumbprintFromCrtShCertificateAsync_AcceptsWildcardSubjectAlternativeNames() {
        const string hostName = "mail.emmasguesthouse.co.za";
        using RSA rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=*.emmasguesthouse.co.za",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        using X509Certificate2 certificate = request.CreateSelfSigned(
            new DateTimeOffset(2026, 3, 26, 0, 3, 0, TimeSpan.Zero),
            new DateTimeOffset(2026, 6, 24, 0, 2, 59, TimeSpan.Zero));
        byte[] certificateBytes = certificate.Export(X509ContentType.Cert);

        var entry = new SubdomainDiscoveryEntry {
            Name = hostName,
            LatestCertificateCtEntryTimestampUtc = new DateTimeOffset(2026, 3, 26, 1, 1, 34, TimeSpan.Zero),
            LatestCertificateSubject = "*.emmasguesthouse.co.za",
            LatestCertificateIssuer = "CN=R13",
            LatestCertificateSerialNumber = "061E581C9CE6E0C0BB18ADCCAF1AF9A99742"
        };
        IReadOnlyList<PassiveCtSourceClient.SourcePayload> payloads = new[] {
            new PassiveCtSourceClient.SourcePayload {
                SourceName = "crt.sh",
                Url = "https://crt.sh/?q=mail.emmasguesthouse.co.za&output=json",
                Payload =
                    """
                    [
                      {
                        "issuer_name": "C=US, O=Let's Encrypt, CN=R13",
                        "common_name": "*.emmasguesthouse.co.za",
                        "name_value": "*.emmasguesthouse.co.za",
                        "id": 25223287523,
                        "entry_timestamp": "2026-03-26T01:01:34.298",
                        "not_before": "2026-03-26T00:03:00",
                        "not_after": "2026-06-24T00:02:59",
                        "serial_number": "061E581C9CE6E0C0BB18ADCCAF1AF9A99742"
                      }
                    ]
                    """
            }
        };

        SubdomainDiscoveryEntry hydrated = await CertificateInventoryCapture.TryHydrateExactCtMetadataThumbprintFromCrtShCertificateAsync(
            entry,
            payloads,
            (downloadId, cancellationToken) => Task.FromResult<byte[]?>(downloadId == "25223287523" ? certificateBytes : null),
            TimeSpan.FromSeconds(5),
            logger: null,
            cancellationToken: CancellationToken.None);

        Assert.Equal(certificate.Thumbprint, hydrated.LatestCertificateThumbprint);
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
    public async Task CaptureAsync_ReplacesOlderCtBundleWhenNewerMetadataArrives() {
        var olderCtEntryTimestamp = new DateTimeOffset(2022, 7, 11, 15, 36, 47, TimeSpan.Zero);
        var newerCtEntryTimestamp = new DateTimeOffset(2024, 8, 12, 9, 15, 0, TimeSpan.Zero);
        var olderNotBefore = new DateTimeOffset(2022, 7, 11, 0, 0, 0, TimeSpan.Zero);
        var olderNotAfter = new DateTimeOffset(2023, 8, 11, 23, 59, 59, TimeSpan.Zero);
        var newerNotBefore = new DateTimeOffset(2024, 8, 12, 0, 0, 0, TimeSpan.Zero);
        var newerNotAfter = new DateTimeOffset(2025, 8, 12, 23, 59, 59, TimeSpan.Zero);

        var capture = new CertificateInventoryCapture {
            CtSubdomainEntryDiscoveryOverride = (domains, options, logger, cancellationToken) => {
                IReadOnlyList<SubdomainDiscoveryEntry> discovered = new[] {
                    new SubdomainDiscoveryEntry {
                        Name = "airtoxics.eurofins.com",
                        FirstSeenUtc = olderCtEntryTimestamp,
                        LastSeenUtc = newerCtEntryTimestamp,
                        LatestCertificateCtEntryTimestampUtc = newerCtEntryTimestamp,
                        LatestCertificateSubject = "CN=airtoxics.eurofins.com-new",
                        LatestCertificateIssuer = "CN=New Issuer",
                        LatestCertificateSerialNumber = "NEW123",
                        LatestCertificateNotBeforeUtc = newerNotBefore,
                        LatestCertificateNotAfterUtc = newerNotAfter,
                        CtSources = new[] { "native-ct" },
                        CertificateObservationCount = 2,
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
                        Expired = true,
                        ChainComplete = false,
                        Protocol = SslProtocols.None,
                        Analysis = new CertificateAnalysis {
                            Url = target,
                            IsReachable = false
                        }
                    });
                }
                return Task.FromResult<IReadOnlyList<CertificateMonitor.Entry>>(entries);
            },
            RecentSnapshotLookupOverride = (options, now, logger) => {
                IReadOnlyList<CertificateInventoryEntry> existing = new[] {
                    new CertificateInventoryEntry {
                        Host = "airtoxics.eurofins.com",
                        ResolvedHost = "airtoxics.eurofins.com",
                        Url = "https://airtoxics.eurofins.com/",
                        Scheme = "https",
                        Port = 443,
                        Service = "HTTPS",
                        CertificateSubject = "CN=airtoxics.eurofins.com-old",
                        CertificateIssuer = "CN=Old Issuer",
                        CertificateSerialNumber = "OLD123",
                        NotBeforeUtc = olderNotBefore,
                        NotAfterUtc = olderNotAfter,
                        PresentInCtLogs = true,
                        CtLatestCertificateEntryTimestampUtc = olderCtEntryTimestamp,
                        CtLatestCertificateSubject = "CN=airtoxics.eurofins.com-old",
                        CtLatestCertificateIssuer = "CN=Old Issuer",
                        CtLatestCertificateSerialNumber = "OLD123",
                        CtLatestCertificateNotBeforeUtc = olderNotBefore,
                        CtLatestCertificateNotAfterUtc = olderNotAfter,
                        CertificateChainSource = "ct-log"
                    }
                };
                return existing.ToDictionary(
                    static entry => "airtoxics.eurofins.com|443|HTTPS",
                    static entry => entry,
                    StringComparer.OrdinalIgnoreCase);
            }
        };

        var options = new CertificateInventoryCaptureOptions {
            IncludeApexHttps = true,
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
            ReuseRecentSnapshotEntries = true,
            RecentSnapshotTtl = TimeSpan.FromDays(365),
            BackfillMissingCtCertificateMetadata = true,
            CtDiscoveryDomains = { "eurofins.com" },
            PersistSnapshot = false
        };

        var result = await capture.CaptureAsync(new[] { "airtoxics.eurofins.com" }, options, cancellationToken: CancellationToken.None);
        var endpoint = Assert.Single(result.Snapshot.Entries);
        Assert.Equal(newerCtEntryTimestamp, endpoint.CtLatestCertificateEntryTimestampUtc);
        Assert.Equal("CN=airtoxics.eurofins.com-new", endpoint.CtLatestCertificateSubject);
        Assert.Equal("CN=New Issuer", endpoint.CtLatestCertificateIssuer);
        Assert.Equal("NEW123", endpoint.CtLatestCertificateSerialNumber);
        Assert.Equal(newerNotBefore, endpoint.CtLatestCertificateNotBeforeUtc);
        Assert.Equal(newerNotAfter, endpoint.CtLatestCertificateNotAfterUtc);
        Assert.Equal("CN=airtoxics.eurofins.com-new", endpoint.CertificateSubject);
        Assert.Equal("CN=New Issuer", endpoint.CertificateIssuer);
        Assert.Equal("NEW123", endpoint.CertificateSerialNumber);
        Assert.Equal(newerNotBefore, endpoint.NotBeforeUtc);
        Assert.Equal(newerNotAfter, endpoint.NotAfterUtc);
    }

    [Fact]
    public async Task CaptureAsync_PreservesPrimaryCertificateBundleWhenNewerCtBundleIsIncomplete() {
        await Task.Yield();

        var olderCtEntryTimestamp = new DateTimeOffset(2022, 7, 11, 15, 36, 47, TimeSpan.Zero);
        var newerCtEntryTimestamp = new DateTimeOffset(2024, 8, 12, 9, 15, 0, TimeSpan.Zero);
        var olderNotBefore = new DateTimeOffset(2022, 7, 11, 0, 0, 0, TimeSpan.Zero);
        var olderNotAfter = new DateTimeOffset(2023, 8, 11, 23, 59, 59, TimeSpan.Zero);

        var entry = new CertificateInventoryEntry {
            Host = "airtoxics.eurofins.com",
            Url = "https://airtoxics.eurofins.com/",
            CertificateSubject = "CN=airtoxics.eurofins.com-old",
            CertificateIssuer = "CN=Old Issuer",
            CertificateSerialNumber = "OLD123",
            NotBeforeUtc = olderNotBefore,
            NotAfterUtc = olderNotAfter,
            PresentInCtLogs = true,
            CtLatestCertificateEntryTimestampUtc = olderCtEntryTimestamp,
            CtLatestCertificateSubject = "CN=airtoxics.eurofins.com-old",
            CtLatestCertificateIssuer = "CN=Old Issuer",
            CtLatestCertificateSerialNumber = "OLD123",
            CtLatestCertificateNotBeforeUtc = olderNotBefore,
            CtLatestCertificateNotAfterUtc = olderNotAfter,
            CertificateChainSource = "ct-log"
        };
        var discoveredEntries = new Dictionary<string, SubdomainDiscoveryEntry>(StringComparer.OrdinalIgnoreCase) {
            ["airtoxics.eurofins.com"] = new SubdomainDiscoveryEntry {
                Name = "airtoxics.eurofins.com",
                LatestCertificateCtEntryTimestampUtc = newerCtEntryTimestamp,
                CtSources = new[] { "native-ct" },
                CertificateObservationCount = 1
            }
        };

        InvokeCtMetadataEnrichment(entry, discoveredEntries);

        Assert.Equal(newerCtEntryTimestamp, entry.CtLatestCertificateEntryTimestampUtc);
        Assert.Equal("CN=airtoxics.eurofins.com-old", entry.CertificateSubject);
        Assert.Equal("CN=Old Issuer", entry.CertificateIssuer);
        Assert.Equal("OLD123", entry.CertificateSerialNumber);
        Assert.Equal(olderNotBefore, entry.NotBeforeUtc);
        Assert.Equal(olderNotAfter, entry.NotAfterUtc);
    }

    [Fact]
    public async Task CaptureAsync_DoesNotMixPrimaryCertificateFieldsFromPartialNewerCtBundle() {
        await Task.Yield();

        var olderCtEntryTimestamp = new DateTimeOffset(2022, 7, 11, 15, 36, 47, TimeSpan.Zero);
        var newerCtEntryTimestamp = new DateTimeOffset(2024, 8, 12, 9, 15, 0, TimeSpan.Zero);
        var olderNotBefore = new DateTimeOffset(2022, 7, 11, 0, 0, 0, TimeSpan.Zero);
        var olderNotAfter = new DateTimeOffset(2023, 8, 11, 23, 59, 59, TimeSpan.Zero);

        var entry = new CertificateInventoryEntry {
            Host = "airtoxics.eurofins.com",
            Url = "https://airtoxics.eurofins.com/",
            CertificateSubject = "CN=airtoxics.eurofins.com-old",
            CertificateIssuer = "CN=Old Issuer",
            CertificateSerialNumber = "OLD123",
            NotBeforeUtc = olderNotBefore,
            NotAfterUtc = olderNotAfter,
            DaysToExpire = -1,
            Expired = true,
            PresentInCtLogs = true,
            CtLatestCertificateEntryTimestampUtc = olderCtEntryTimestamp,
            CtLatestCertificateSubject = "CN=airtoxics.eurofins.com-old",
            CtLatestCertificateIssuer = "CN=Old Issuer",
            CtLatestCertificateSerialNumber = "OLD123",
            CtLatestCertificateNotBeforeUtc = olderNotBefore,
            CtLatestCertificateNotAfterUtc = olderNotAfter,
            CertificateChainSource = "ct-log"
        };
        var discoveredEntries = new Dictionary<string, SubdomainDiscoveryEntry>(StringComparer.OrdinalIgnoreCase) {
            ["airtoxics.eurofins.com"] = new SubdomainDiscoveryEntry {
                Name = "airtoxics.eurofins.com",
                LatestCertificateCtEntryTimestampUtc = newerCtEntryTimestamp,
                LatestCertificateSubject = "CN=airtoxics.eurofins.com-new",
                LatestCertificateIssuer = "CN=New Issuer",
                LatestCertificateSerialNumber = "NEW123",
                LatestCertificateNotBeforeUtc = new DateTimeOffset(2024, 8, 1, 0, 0, 0, TimeSpan.Zero),
                CtSources = new[] { "native-ct" },
                CertificateObservationCount = 1
            }
        };

        InvokeCtMetadataEnrichment(entry, discoveredEntries);

        Assert.Equal(newerCtEntryTimestamp, entry.CtLatestCertificateEntryTimestampUtc);
        Assert.Equal("CN=airtoxics.eurofins.com-old", entry.CertificateSubject);
        Assert.Equal("CN=Old Issuer", entry.CertificateIssuer);
        Assert.Equal("OLD123", entry.CertificateSerialNumber);
        Assert.Equal(olderNotBefore, entry.NotBeforeUtc);
        Assert.Equal(olderNotAfter, entry.NotAfterUtc);
        Assert.True(entry.Expired);
        Assert.True(entry.DaysToExpire <= 0);
    }

    [Fact]
    public async Task CaptureAsync_PreservesExistingBundleWhenCtLatestTimestampsAreMissing() {
        await Task.Yield();

        var olderNotBefore = new DateTimeOffset(2022, 7, 11, 0, 0, 0, TimeSpan.Zero);
        var olderNotAfter = new DateTimeOffset(2023, 8, 11, 23, 59, 59, TimeSpan.Zero);

        var entry = new CertificateInventoryEntry {
            Host = "airtoxics.eurofins.com",
            Url = "https://airtoxics.eurofins.com/",
            CertificateSubject = "CN=airtoxics.eurofins.com-old",
            CertificateIssuer = "CN=Old Issuer",
            CertificateSerialNumber = "OLD123",
            NotBeforeUtc = olderNotBefore,
            NotAfterUtc = olderNotAfter,
            PresentInCtLogs = true,
            CtLatestCertificateSubject = "CN=airtoxics.eurofins.com-old",
            CtLatestCertificateIssuer = "CN=Old Issuer",
            CtLatestCertificateSerialNumber = "OLD123",
            CtLatestCertificateNotBeforeUtc = olderNotBefore,
            CtLatestCertificateNotAfterUtc = olderNotAfter,
            CertificateChainSource = "ct-log"
        };
        var discoveredEntries = new Dictionary<string, SubdomainDiscoveryEntry>(StringComparer.OrdinalIgnoreCase) {
            ["airtoxics.eurofins.com"] = new SubdomainDiscoveryEntry {
                Name = "airtoxics.eurofins.com",
                CtSources = new[] { "native-ct" },
                CertificateObservationCount = 1
            }
        };

        InvokeCtMetadataEnrichment(entry, discoveredEntries);

        Assert.Null(entry.CtLatestCertificateEntryTimestampUtc);
        Assert.Equal("CN=airtoxics.eurofins.com-old", entry.CtLatestCertificateSubject);
        Assert.Equal("CN=airtoxics.eurofins.com-old", entry.CertificateSubject);
        Assert.Equal("CN=Old Issuer", entry.CertificateIssuer);
        Assert.Equal("OLD123", entry.CertificateSerialNumber);
        Assert.Equal(olderNotBefore, entry.NotBeforeUtc);
        Assert.Equal(olderNotAfter, entry.NotAfterUtc);
    }

    [Fact]
    public async Task CaptureAsync_HydratesPrimaryCertificateSignalsFromCtBundleAsync() {
        await Task.Yield();

        var ctEntryTimestamp = new DateTimeOffset(2024, 8, 12, 9, 15, 0, TimeSpan.Zero);
        var notBefore = new DateTimeOffset(2024, 8, 1, 0, 0, 0, TimeSpan.Zero);
        var notAfter = new DateTimeOffset(2025, 8, 1, 0, 0, 0, TimeSpan.Zero);

        var entry = new CertificateInventoryEntry {
            Host = "airtoxics.eurofins.com",
            Url = "https://airtoxics.eurofins.com/",
            PresentInCtLogs = true,
            CertificateChainSource = "ct-log"
        };
        var discoveredEntries = new Dictionary<string, SubdomainDiscoveryEntry>(StringComparer.OrdinalIgnoreCase) {
            ["airtoxics.eurofins.com"] = new SubdomainDiscoveryEntry {
                Name = "airtoxics.eurofins.com",
                LatestCertificateCtEntryTimestampUtc = ctEntryTimestamp,
                LatestCertificateThumbprint = "AA11BB22CC33DD44EE55FF6677889900AA11BB22",
                LatestCertificateSubjectAlternativeNames = new[] { "airtoxics.eurofins.com", "www.airtoxics.eurofins.com" },
                LatestCertificateSubject = "CN=airtoxics.eurofins.com",
                LatestCertificateIssuer = "CN=CT Issuer",
                LatestCertificateSerialNumber = "CT-12345",
                LatestCertificateNotBeforeUtc = notBefore,
                LatestCertificateNotAfterUtc = notAfter,
                LatestCertificateIsSelfSigned = true,
                LatestCertificateWeakKey = true,
                LatestCertificateSha1Signature = true,
                LatestCertificateHasServerAuthentication = true,
                LatestCertificateHasClientAuthentication = false,
                LatestCertificateHasSecureEmail = false,
                LatestCertificateAuthenticationProfile = CertificateAuthenticationProfileClassifier.ServerAuthOnly,
                CtSources = new[] { "native-ct" },
                CertificateObservationCount = 1
            }
        };

        InvokeCtMetadataEnrichment(entry, discoveredEntries);

        Assert.Equal("AA11BB22CC33DD44EE55FF6677889900AA11BB22", entry.CertificateThumbprint);
        Assert.Equal("CN=airtoxics.eurofins.com", entry.CertificateSubject);
        Assert.Equal("CN=CT Issuer", entry.CertificateIssuer);
        Assert.Equal("CT-12345", entry.CertificateSerialNumber);
        Assert.Equal(notBefore, entry.NotBeforeUtc);
        Assert.Equal(notAfter, entry.NotAfterUtc);
        Assert.Equal(
            new[] { "airtoxics.eurofins.com", "www.airtoxics.eurofins.com" },
            entry.SubjectAlternativeNames);
        Assert.True(entry.IsSelfSigned);
        Assert.True(entry.WeakKey);
        Assert.True(entry.Sha1Signature);
        Assert.True(entry.AllowsServerAuthentication);
        Assert.False(entry.AllowsClientAuthentication);
        Assert.False(entry.AllowsSecureEmail);
        Assert.Equal(CertificateAuthenticationProfileClassifier.ServerAuthOnly, entry.AuthenticationProfile);
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

    [Fact]
    public async Task CaptureAsync_KeepsCtDiscoveredCountersConsistentWhenExactHostRescueAddsMetadata() {
        PassiveCtSourceClient.ResetSharedStateForTesting();
        try {
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

        Assert.Equal(1, result.CtDiscoveredSubdomainCount);
        Assert.Contains("airtoxics.eurofins.com", result.CtDiscoveredSubdomains, StringComparer.OrdinalIgnoreCase);
        var discovered = Assert.Single(result.CtDiscoveredSubdomainEntries);
        Assert.Equal("airtoxics.eurofins.com", discovered.Name);
        Assert.Equal("CN=airtoxics.eurofins.com", discovered.LatestCertificateSubject);
        } finally {
            PassiveCtSourceClient.ResetSharedStateForTesting();
        }
    }

    [Fact]
    public async Task CaptureAsync_SkipsRedundantExactHostPassiveBackfillWhenCtDiscoveryAlreadyHydratedSeed() {
        var ctFirstSeen = new DateTimeOffset(2026, 3, 5, 10, 21, 27, TimeSpan.Zero);
        var ctLastSeen = new DateTimeOffset(2026, 3, 5, 15, 42, 37, TimeSpan.Zero);
        var passiveCtEntryTimestamp = new DateTimeOffset(2022, 7, 11, 15, 36, 47, TimeSpan.Zero);
        var notBefore = new DateTimeOffset(2022, 7, 11, 0, 0, 0, TimeSpan.Zero);
        var notAfter = new DateTimeOffset(2023, 8, 11, 23, 59, 59, TimeSpan.Zero);
        var passiveQueries = new List<string>();
        const string thumbprint = "AA11BB22CC33DD44EE55FF6677889900AA11BB22";

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
                string target = Assert.Single(domains);
                passiveQueries.Add(target);
                IReadOnlyList<SubdomainDiscoveryEntry> discovered = string.Equals(target, "eurofins.com", StringComparison.OrdinalIgnoreCase)
                    ? new[] {
                        new SubdomainDiscoveryEntry {
                            Name = "airtoxics.eurofins.com",
                            FirstSeenUtc = passiveCtEntryTimestamp,
                            LastSeenUtc = passiveCtEntryTimestamp,
                            LatestCertificateCtEntryTimestampUtc = passiveCtEntryTimestamp,
                            LatestCertificateThumbprint = thumbprint,
                            LatestCertificateSubject = "CN=airtoxics.eurofins.com",
                            LatestCertificateIssuer = "CN=Sectigo RSA Domain Validation Secure Server CA, O=Sectigo Limited, C=GB",
                            LatestCertificateSerialNumber = "0CE4A3C00C1DD4890B9EBA4223FE917F",
                            LatestCertificateNotBeforeUtc = notBefore,
                            LatestCertificateNotAfterUtc = notAfter,
                            LatestCertificateHasServerAuthentication = true,
                            LatestCertificateHasClientAuthentication = false,
                            LatestCertificateHasSecureEmail = false,
                            LatestCertificateAuthenticationProfile = CertificateAuthenticationProfileClassifier.ServerAuthOnly,
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
            IncludeApexHttps = true,
            IncludeWwwHttps = false,
            IncludeCtDiscoveredSubdomains = true,
            VerifyCtDiscoveredSubdomains = false,
            EnablePassiveCtFallback = true,
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

        var result = await capture.CaptureAsync(new[] { "eurofins.com", "airtoxics.eurofins.com" }, options, cancellationToken: CancellationToken.None);

        Assert.Equal(new[] { "eurofins.com" }, passiveQueries);
        Assert.Equal(1, result.CtDiscoveredSubdomainCount);
        Assert.Equal(0, result.CtPromotedHttpsCount);
        Assert.Equal(1, result.CtSkippedHttpsPromotionCount);
        Assert.Equal(0, result.CtSkippedUnresolvedHttpsPromotionCount);
        Assert.Equal(0, result.CtSkippedLowConfidenceHttpsPromotionCount);
        Assert.Equal(1, result.CtSkippedDuplicateHttpsPromotionCount);
        var endpoint = Assert.Single(result.Snapshot.Entries, entry => entry.Host.Equals("airtoxics.eurofins.com", StringComparison.OrdinalIgnoreCase));
        Assert.Contains("ct-discovery", endpoint.TargetOrigins, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("seed-exact-host", endpoint.TargetOrigins, StringComparer.OrdinalIgnoreCase);
        Assert.Equal("live-probe", endpoint.CaptureDisposition);
        Assert.Equal("CN=airtoxics.eurofins.com", endpoint.CertificateSubject);
        Assert.Equal(passiveCtEntryTimestamp, endpoint.CtLatestCertificateEntryTimestampUtc);
    }

    [Fact]
    public async Task CaptureAsync_ExactHostPassiveBackfillRunsWhenCtDiscoveryOnlyHasIdentityMetadata() {
        var ctFirstSeen = new DateTimeOffset(2026, 3, 5, 10, 21, 27, TimeSpan.Zero);
        var ctLastSeen = new DateTimeOffset(2026, 3, 5, 15, 42, 37, TimeSpan.Zero);
        var passiveCtEntryTimestamp = new DateTimeOffset(2022, 7, 11, 15, 36, 47, TimeSpan.Zero);
        var notBefore = new DateTimeOffset(2022, 7, 11, 0, 0, 0, TimeSpan.Zero);
        var notAfter = new DateTimeOffset(2023, 8, 11, 23, 59, 59, TimeSpan.Zero);
        var passiveQueries = new List<string>();
        const string thumbprint = "AA11BB22CC33DD44EE55FF6677889900AA11BB22";

        var capture = new CertificateInventoryCapture {
            CtSubdomainEntryDiscoveryOverride = (domains, options, logger, cancellationToken) => {
                IReadOnlyList<SubdomainDiscoveryEntry> discovered = new[] {
                    new SubdomainDiscoveryEntry {
                        Name = "airtoxics.eurofins.com",
                        FirstSeenUtc = ctFirstSeen,
                        LastSeenUtc = ctLastSeen,
                        LatestCertificateCtEntryTimestampUtc = passiveCtEntryTimestamp,
                        LatestCertificateSubject = "CN=airtoxics.eurofins.com",
                        LatestCertificateIssuer = "CN=Identity Only Issuer",
                        LatestCertificateSerialNumber = "IDENTITY-ONLY-123",
                        LatestCertificateNotBeforeUtc = notBefore,
                        LatestCertificateNotAfterUtc = notAfter,
                        CtSources = new[] { "native-ct" },
                        CertificateObservationCount = 2,
                        ResolutionStatus = SubdomainResolutionStatus.Resolves
                    }
                };
                return Task.FromResult(discovered);
            },
            CtPassiveMetadataBackfillOverride = (domains, options, logger, cancellationToken) => {
                string target = Assert.Single(domains);
                passiveQueries.Add(target);
                IReadOnlyList<SubdomainDiscoveryEntry> discovered = string.Equals(target, "airtoxics.eurofins.com", StringComparison.OrdinalIgnoreCase)
                    ? new[] {
                        new SubdomainDiscoveryEntry {
                            Name = "airtoxics.eurofins.com",
                            FirstSeenUtc = passiveCtEntryTimestamp,
                            LastSeenUtc = passiveCtEntryTimestamp,
                            LatestCertificateCtEntryTimestampUtc = passiveCtEntryTimestamp,
                            LatestCertificateThumbprint = thumbprint,
                            LatestCertificateSubject = "CN=airtoxics.eurofins.com",
                            LatestCertificateIssuer = "CN=Sectigo RSA Domain Validation Secure Server CA, O=Sectigo Limited, C=GB",
                            LatestCertificateSerialNumber = "0CE4A3C00C1DD4890B9EBA4223FE917F",
                            LatestCertificateNotBeforeUtc = notBefore,
                            LatestCertificateNotAfterUtc = notAfter,
                            LatestCertificateHasServerAuthentication = true,
                            LatestCertificateHasClientAuthentication = false,
                            LatestCertificateHasSecureEmail = false,
                            LatestCertificateAuthenticationProfile = CertificateAuthenticationProfileClassifier.ServerAuthOnly,
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
            IncludeApexHttps = true,
            IncludeWwwHttps = false,
            IncludeCtDiscoveredSubdomains = true,
            VerifyCtDiscoveredSubdomains = false,
            EnablePassiveCtFallback = true,
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

        var result = await capture.CaptureAsync(new[] { "eurofins.com", "airtoxics.eurofins.com" }, options, cancellationToken: CancellationToken.None);

        Assert.Equal(new[] { "eurofins.com", "airtoxics.eurofins.com" }, passiveQueries);
        var discovered = Assert.Single(result.CtDiscoveredSubdomainEntries, entry => entry.Name.Equals("airtoxics.eurofins.com", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(thumbprint, discovered.LatestCertificateThumbprint);
        Assert.Equal(CertificateAuthenticationProfileClassifier.ServerAuthOnly, discovered.LatestCertificateAuthenticationProfile);
        var endpoint = Assert.Single(result.Snapshot.Entries, entry => entry.Host.Equals("airtoxics.eurofins.com", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(thumbprint, endpoint.CertificateThumbprint);
        Assert.Equal(CertificateAuthenticationProfileClassifier.ServerAuthOnly, endpoint.AuthenticationProfile);
    }

    [IntegrationFact]
    public async Task CaptureAsync_CtEvidenceRefreshProfile_HydratesExactHostFromLiveCtSources() {
        const string hostName = "api.github.com";

        var capture = new CertificateInventoryCapture {
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
            EnablePassiveCtMetadataFallback = true,
            EnableCrtShPostgreSqlMetadataFallback = true,
            BackfillMissingCtCertificateMetadata = true,
            PersistSnapshot = false,
            CrtShPostgreSqlCommandTimeoutSeconds = 20,
            PassiveCtRequestTimeout = TimeSpan.FromSeconds(20)
        }.ApplyCtEvidenceRefreshProfile();

        var result = await capture.CaptureAsync(new[] { hostName }, options, cancellationToken: CancellationToken.None);

        var endpoint = Assert.Single(result.Snapshot.Entries, entry => entry.Host.Equals(hostName, StringComparison.OrdinalIgnoreCase));
        Assert.False(endpoint.IsReachable);
        Assert.True(endpoint.PresentInCtLogs);
        Assert.False(string.IsNullOrWhiteSpace(endpoint.CertificateThumbprint));
        Assert.False(string.IsNullOrWhiteSpace(endpoint.CertificateSubject));
        Assert.False(string.IsNullOrWhiteSpace(endpoint.CertificateIssuer));
        Assert.False(string.IsNullOrWhiteSpace(endpoint.CertificateSerialNumber));
        Assert.True(endpoint.NotBeforeUtc.HasValue);
        Assert.True(endpoint.NotAfterUtc.HasValue);
        Assert.False(string.IsNullOrWhiteSpace(endpoint.AuthenticationProfile));
        Assert.Contains(
            endpoint.CtDiscoverySources,
            source => source.Equals("crt.sh", StringComparison.OrdinalIgnoreCase) ||
                      source.Equals("crt.sh-db", StringComparison.OrdinalIgnoreCase) ||
                      source.Equals("certspotter", StringComparison.OrdinalIgnoreCase));

        Console.WriteLine($"Host={endpoint.Host}");
        Console.WriteLine($"Reachable={endpoint.IsReachable}");
        Console.WriteLine($"PresentInCtLogs={endpoint.PresentInCtLogs}");
        Console.WriteLine($"Thumbprint={endpoint.CertificateThumbprint}");
        Console.WriteLine($"Subject={endpoint.CertificateSubject}");
        Console.WriteLine($"Issuer={endpoint.CertificateIssuer}");
        Console.WriteLine($"Serial={endpoint.CertificateSerialNumber}");
        Console.WriteLine($"NotBeforeUtc={endpoint.NotBeforeUtc:O}");
        Console.WriteLine($"NotAfterUtc={endpoint.NotAfterUtc:O}");
        Console.WriteLine($"AuthenticationProfile={endpoint.AuthenticationProfile}");
        Console.WriteLine($"AllowsServerAuthentication={endpoint.AllowsServerAuthentication}");
        Console.WriteLine($"CtSources={string.Join(", ", endpoint.CtDiscoverySources)}");
    }

    [IntegrationFact]
    public async Task CaptureAsync_CtEvidenceRefreshProfile_HydratesEurofinsExactHostFromLivePassiveCtSources() {
        const string hostName = "eurofins.com";
        PassiveCtSourceClient.ResetSharedStateForTesting();

        var capture = new CertificateInventoryCapture {
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
            EnablePassiveCtMetadataFallback = true,
            EnableCrtShPostgreSqlMetadataFallback = false,
            BackfillMissingCtCertificateMetadata = true,
            PersistSnapshot = false,
            PassiveCtRequestTimeout = TimeSpan.FromSeconds(45),
            PassiveCtRetryCount = 0,
            PassiveCtCrtShMinimumSpacing = TimeSpan.Zero,
            PassiveCtCertSpotterMinimumSpacing = TimeSpan.Zero,
            PassiveCtCrtShMaximumRequestsPerRun = 1,
            PassiveCtCertSpotterMaximumRequestsPerRun = 1
        }.ApplyCtEvidenceRefreshProfile();
        options.ExactPassiveCtMetadataTargetHosts.Add(hostName);

        var result = await capture.CaptureAsync(new[] { hostName }, options, cancellationToken: CancellationToken.None);

        var endpoint = Assert.Single(result.Snapshot.Entries, entry => entry.Host.Equals(hostName, StringComparison.OrdinalIgnoreCase));
        string diagnostics = string.Join(
            Environment.NewLine,
            result.PassiveCtDiagnosticEntries.Select(diagnostic =>
                $"{diagnostic.QueryKind}:{diagnostic.SourceName}:{diagnostic.State}:{diagnostic.Failure}"));
        Assert.False(endpoint.IsReachable);
        Assert.True(endpoint.PresentInCtLogs, "Expected live passive CT metadata for eurofins.com." + Environment.NewLine + diagnostics);
        Assert.False(string.IsNullOrWhiteSpace(endpoint.CertificateThumbprint), diagnostics);
        Assert.False(string.IsNullOrWhiteSpace(endpoint.CertificateSubject), diagnostics);
        Assert.False(string.IsNullOrWhiteSpace(endpoint.CertificateIssuer), diagnostics);
        Assert.False(string.IsNullOrWhiteSpace(endpoint.CertificateSerialNumber), diagnostics);
        Assert.True(endpoint.NotBeforeUtc.HasValue, diagnostics);
        Assert.True(endpoint.NotAfterUtc.HasValue, diagnostics);
        Assert.False(string.IsNullOrWhiteSpace(endpoint.AuthenticationProfile), diagnostics);
        Assert.True(
            endpoint.CtDiscoverySources.Any(source =>
                source.Equals("crt.sh", StringComparison.OrdinalIgnoreCase) ||
                source.Equals("certspotter", StringComparison.OrdinalIgnoreCase)),
            "Expected crt.sh or CertSpotter source evidence." + Environment.NewLine + diagnostics);

        Console.WriteLine($"Host={endpoint.Host}");
        Console.WriteLine($"PresentInCtLogs={endpoint.PresentInCtLogs}");
        Console.WriteLine($"Thumbprint={endpoint.CertificateThumbprint}");
        Console.WriteLine($"Subject={endpoint.CertificateSubject}");
        Console.WriteLine($"Issuer={endpoint.CertificateIssuer}");
        Console.WriteLine($"Serial={endpoint.CertificateSerialNumber}");
        Console.WriteLine($"NotBeforeUtc={endpoint.NotBeforeUtc:O}");
        Console.WriteLine($"NotAfterUtc={endpoint.NotAfterUtc:O}");
        Console.WriteLine($"AuthenticationProfile={endpoint.AuthenticationProfile}");
        Console.WriteLine($"CtSources={string.Join(", ", endpoint.CtDiscoverySources)}");
        Console.WriteLine(diagnostics);
    }

    [IntegrationFact]
    public async Task CaptureAsync_CtDiscoveryOnlyProfile_DiscoversEurofinsSubdomainsFromLivePassiveCtSources() {
        const string domainName = "eurofins.com";
        PassiveCtSourceClient.ResetSharedStateForTesting();

        var capture = new CertificateInventoryCapture();
        var options = new CertificateInventoryCaptureOptions {
            PersistSnapshot = false,
            PassiveCtRequestTimeout = TimeSpan.FromSeconds(45),
            PassiveCtRetryCount = 0,
            PassiveCtCrtShMinimumSpacing = TimeSpan.Zero,
            PassiveCtCertSpotterMinimumSpacing = TimeSpan.Zero,
            PassiveCtCrtShMaximumRequestsPerRun = 1,
            PassiveCtCertSpotterMaximumRequestsPerRun = 1,
            MaxCtRowsPerDomain = 500,
            MaxCtSubdomainsPerDomain = 50
        }.ApplyCtDiscoveryOnlyProfile();
        options.EnableNativeCtLogSubdomainSource = false;
        options.BackfillMissingCtCertificateMetadata = false;

        var result = await capture.CaptureAsync(new[] { domainName }, options, cancellationToken: CancellationToken.None);

        string diagnostics = string.Join(
            Environment.NewLine,
            result.PassiveCtDiagnosticEntries.Select(diagnostic =>
                $"{diagnostic.QueryKind}:{diagnostic.SourceName}:{diagnostic.State}:{diagnostic.Failure}"));
        Assert.NotEmpty(result.CtDiscoveredSubdomainEntries);
        Assert.Contains(
            result.CtDiscoveredSubdomainEntries,
            entry => entry.Name.EndsWith("." + domainName, StringComparison.OrdinalIgnoreCase));
        Assert.Contains(
            result.CtDiscoveredSubdomainEntries,
            entry => entry.CtSources.Any(source =>
                source.Equals("crt.sh", StringComparison.OrdinalIgnoreCase) ||
                source.Equals("certspotter", StringComparison.OrdinalIgnoreCase)));

        foreach (var entry in result.CtDiscoveredSubdomainEntries.Take(10)) {
            Console.WriteLine(
                $"Subdomain={entry.Name}; Sources={string.Join(", ", entry.CtSources)}; Observations={entry.CertificateObservationCount}; NotBefore={entry.LatestCertificateNotBeforeUtc:O}; NotAfter={entry.LatestCertificateNotAfterUtc:O}");
        }
        Console.WriteLine(diagnostics);
    }

    [Fact]
    public void PassiveCtRunSuppressionReason_RequiresBothSharedSourcesToBeBlocked()
    {
        var diagnostics = new[]
        {
            new PassiveCtDiagnosticEntry
            {
                SourceName = "crt.sh",
                State = "CoolingDown",
                RetrySuggested = true,
                CooldownUntilUtc = DateTimeOffset.UtcNow.AddMinutes(2)
            },
            new PassiveCtDiagnosticEntry
            {
                SourceName = "certspotter",
                State = "Succeeded",
                RetrySuggested = false
            }
        };

        object?[] arguments = { diagnostics, null };
        var method = typeof(CertificateInventoryCapture).GetMethod(
            "TryBuildPassiveCtRunSuppressionReason",
            BindingFlags.NonPublic | BindingFlags.Static);

        Assert.NotNull(method);
        bool result = (bool)method!.Invoke(null, arguments)!;

        Assert.False(result);
        Assert.True(string.IsNullOrEmpty(arguments[1] as string));
    }

    [Fact]
    public void PassiveCtRunSuppressionReason_TriggersWhenBothSharedSourcesAreCoolingDown()
    {
        var diagnostics = new[]
        {
            new PassiveCtDiagnosticEntry
            {
                SourceName = "crt.sh",
                State = "RateLimited",
                RetrySuggested = true,
                CooldownUntilUtc = DateTimeOffset.UtcNow.AddMinutes(2)
            },
            new PassiveCtDiagnosticEntry
            {
                SourceName = "certspotter",
                State = "CoolingDown",
                RetrySuggested = true,
                CooldownUntilUtc = DateTimeOffset.UtcNow.AddMinutes(5)
            }
        };

        object?[] arguments = { diagnostics, null };
        var method = typeof(CertificateInventoryCapture).GetMethod(
            "TryBuildPassiveCtRunSuppressionReason",
            BindingFlags.NonPublic | BindingFlags.Static);

        Assert.NotNull(method);
        bool result = (bool)method!.Invoke(null, arguments)!;

        Assert.True(result);
        string reason = Assert.IsType<string>(arguments[1]);
        Assert.Contains("crt.sh", reason, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("certspotter", reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void PassiveCtRunSuppressionReason_DoesNotTriggerForInvalidPayloadDiagnostics()
    {
        var diagnostics = new[]
        {
            new PassiveCtDiagnosticEntry
            {
                SourceName = "crt.sh",
                State = "InvalidPayload",
                RetrySuggested = true
            },
            new PassiveCtDiagnosticEntry
            {
                SourceName = "certspotter",
                State = "InvalidPayload",
                RetrySuggested = true
            }
        };

        object?[] arguments = { diagnostics, null };
        var method = typeof(CertificateInventoryCapture).GetMethod(
            "TryBuildPassiveCtRunSuppressionReason",
            BindingFlags.NonPublic | BindingFlags.Static);

        Assert.NotNull(method);
        bool result = (bool)method!.Invoke(null, arguments)!;

        Assert.False(result);
        Assert.True(string.IsNullOrEmpty(arguments[1] as string));
    }

    [Theory]
    [InlineData("ww.example.com", true)]
    [InlineData("www.example.com", false)]
    [InlineData("wwww.example.com", true)]
    [InlineData("wwwww.example.com", false)]
    public void LooksLikeLowConfidenceCtOnlyProbeVariant_MatchesExpectedNoiseLabels(string host, bool expected)
    {
        var method = typeof(CertificateInventoryCapture).GetMethod(
            "LooksLikeLowConfidenceCtOnlyProbeVariant",
            BindingFlags.NonPublic | BindingFlags.Static);

        Assert.NotNull(method);
        bool result = (bool)method!.Invoke(null, new object?[] { host })!;

        Assert.Equal(expected, result);
    }

    [Fact]
    public async Task CaptureAsync_UsesCtDiscoveryScopeOverrideButStillProbesExactHostSeeds()
    {
        IReadOnlyList<string>? ctDiscoveryDomains = null;
        IReadOnlyList<string>? httpsProbeTargets = null;
        var capture = new CertificateInventoryCapture
        {
            CtSubdomainEntryDiscoveryOverride = (domains, options, logger, cancellationToken) =>
            {
                ctDiscoveryDomains = domains.ToList();
                return Task.FromResult<IReadOnlyList<SubdomainDiscoveryEntry>>(Array.Empty<SubdomainDiscoveryEntry>());
            },
            HttpsProbeOverride = (httpsTargets, options, logger, cancellationToken) =>
            {
                httpsProbeTargets = httpsTargets.ToList();
                return Task.FromResult<IReadOnlyList<CertificateMonitor.Entry>>(Array.Empty<CertificateMonitor.Entry>());
            }
        };

        var options = new CertificateInventoryCaptureOptions
        {
            IncludeApexHttps = true,
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
        options.CtDiscoveryDomains.Add("eurofins.com");

        await capture.CaptureAsync(
            new[] { "eurofins.com", "airtoxics.eurofins.com" },
            options,
            cancellationToken: CancellationToken.None);

        Assert.Equal(new[] { "eurofins.com" }, ctDiscoveryDomains);
        Assert.NotNull(httpsProbeTargets);
        Assert.Contains("https://eurofins.com/", httpsProbeTargets!, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("https://airtoxics.eurofins.com/", httpsProbeTargets!, StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ExactCtMetadataBackfill_SkipsWhenSharedPassiveSourcesAreCoolingDown()
    {
        var capture = new CertificateInventoryCapture
        {
            CtPassiveMetadataBackfillOverride = (_, _, _, _) =>
                throw new InvalidOperationException("Passive CT exact metadata query should have been suppressed.")
        };
        var method = typeof(CertificateInventoryCapture).GetMethod(
            "BackfillMissingCtCertificateMetadataExactAsync",
            BindingFlags.NonPublic | BindingFlags.Instance);

        Assert.NotNull(method);

        var warnings = new List<string>();
        var diagnostics = new List<PassiveCtDiagnosticEntry>
        {
            new()
            {
                SourceName = "crt.sh",
                State = "CoolingDown",
                RetrySuggested = true,
                CooldownUntilUtc = DateTimeOffset.UtcNow.AddMinutes(2)
            },
            new()
            {
                SourceName = "certspotter",
                State = "RateLimited",
                RetrySuggested = true,
                CooldownUntilUtc = DateTimeOffset.UtcNow.AddMinutes(5)
            }
        };
        var options = new CertificateInventoryCaptureOptions
        {
            EnablePassiveCtFallback = true,
            EnablePassiveCtMetadataFallback = true
        };

        Task<IReadOnlyList<SubdomainDiscoveryEntry>> task =
            (Task<IReadOnlyList<SubdomainDiscoveryEntry>>)method!.Invoke(
                capture,
                new object[]
                {
                    new[] { "api.example.com", "portal.example.com" },
                    options,
                    warnings,
                    diagnostics,
                    new InternalLogger(false),
                    CancellationToken.None
                })!;

        IReadOnlyList<SubdomainDiscoveryEntry> result = await task;

        Assert.Empty(result);
        Assert.Contains(
            warnings,
            warning => warning.Contains("Passive CT exact metadata backfill skipped", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task ExactCtMetadataBackfill_UsesDirectPostgreSqlMetadataBeforePassiveCooldownSuppression()
    {
        var capture = new CertificateInventoryCapture
        {
            CtExactMetadataPostgreSqlOverride = (host, options, logger, cancellationToken) =>
                Task.FromResult<SubdomainDiscoveryEntry?>(new SubdomainDiscoveryEntry
                {
                    Name = host,
                    LatestCertificateThumbprint = "AA11BB22CC33DD44EE55FF6677889900AABBCCDD",
                    LatestCertificateSubject = "CN=api.example.com",
                    LatestCertificateIssuer = "CN=crt.sh-db",
                    CtSources = new[] { "crt.sh-db" },
                    CertificateObservationCount = 1
                }),
            CtPassiveMetadataBackfillOverride = (_, _, _, _) =>
                throw new InvalidOperationException("Passive CT exact metadata query should not have been needed.")
        };
        var method = typeof(CertificateInventoryCapture).GetMethod(
            "BackfillMissingCtCertificateMetadataExactAsync",
            BindingFlags.NonPublic | BindingFlags.Instance);

        Assert.NotNull(method);

        var warnings = new List<string>();
        var diagnostics = new List<PassiveCtDiagnosticEntry>
        {
            new()
            {
                SourceName = "crt.sh",
                State = "CoolingDown",
                RetrySuggested = true,
                CooldownUntilUtc = DateTimeOffset.UtcNow.AddMinutes(2)
            },
            new()
            {
                SourceName = "certspotter",
                State = "RateLimited",
                RetrySuggested = true,
                CooldownUntilUtc = DateTimeOffset.UtcNow.AddMinutes(5)
            }
        };
        var options = new CertificateInventoryCaptureOptions
        {
            EnablePassiveCtFallback = true,
            EnablePassiveCtMetadataFallback = true,
            EnableCrtShPostgreSqlMetadataFallback = true
        };

        Task<IReadOnlyList<SubdomainDiscoveryEntry>> task =
            (Task<IReadOnlyList<SubdomainDiscoveryEntry>>)method!.Invoke(
                capture,
                new object[]
                {
                    new[] { "api.example.com" },
                    options,
                    warnings,
                    diagnostics,
                    new InternalLogger(false),
                    CancellationToken.None
                })!;

        IReadOnlyList<SubdomainDiscoveryEntry> result = await task;

        SubdomainDiscoveryEntry entry = Assert.Single(result);
        Assert.Equal("api.example.com", entry.Name);
        Assert.Equal("AA11BB22CC33DD44EE55FF6677889900AABBCCDD", entry.LatestCertificateThumbprint);
        Assert.DoesNotContain(
            warnings,
            warning => warning.Contains("Passive CT exact metadata backfill skipped", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task ExactCtMetadataBackfill_UsesDirectPostgreSqlMetadataWhenPassiveFallbackIsDisabled() {
        var passiveFallbackCalled = false;
        var capture = new CertificateInventoryCapture
        {
            CtExactMetadataPostgreSqlOverride = (host, options, logger, cancellationToken) =>
                Task.FromResult<SubdomainDiscoveryEntry?>(new SubdomainDiscoveryEntry
                {
                    Name = host,
                    LatestCertificateThumbprint = "DBONLY11223344556677889900AABBCCDDEEFF",
                    LatestCertificateSubject = "CN=api.example.com",
                    LatestCertificateIssuer = "CN=crt.sh-db",
                    CtSources = new[] { "crt.sh-db" },
                    CertificateObservationCount = 1
                }),
            CtPassiveMetadataBackfillOverride = (_, _, _, _) =>
            {
                passiveFallbackCalled = true;
                return Task.FromResult<IReadOnlyList<SubdomainDiscoveryEntry>>(Array.Empty<SubdomainDiscoveryEntry>());
            }
        };
        var method = typeof(CertificateInventoryCapture).GetMethod(
            "BackfillMissingCtCertificateMetadataExactAsync",
            BindingFlags.NonPublic | BindingFlags.Instance);

        Assert.NotNull(method);

        var options = new CertificateInventoryCaptureOptions
        {
            EnablePassiveCtFallback = false,
            EnablePassiveCtMetadataFallback = false,
            EnableCrtShPostgreSqlMetadataFallback = true
        };

        Task<IReadOnlyList<SubdomainDiscoveryEntry>> task =
            (Task<IReadOnlyList<SubdomainDiscoveryEntry>>)method!.Invoke(
                capture,
                new object[]
                {
                    new[] { "api.example.com" },
                    options,
                    new List<string>(),
                    new List<PassiveCtDiagnosticEntry>(),
                    new InternalLogger(false),
                    CancellationToken.None
                })!;

        IReadOnlyList<SubdomainDiscoveryEntry> result = await task;

        SubdomainDiscoveryEntry entry = Assert.Single(result);
        Assert.Equal("api.example.com", entry.Name);
        Assert.Equal("DBONLY11223344556677889900AABBCCDDEEFF", entry.LatestCertificateThumbprint);
        Assert.False(passiveFallbackCalled);
    }

    [Fact]
    public async Task ExactCtMetadataBackfill_PropagatesCancellationDuringPassiveExactLookup()
    {
        var capture = new CertificateInventoryCapture
        {
            CtPassiveMetadataBackfillOverride = async (_, _, _, cancellationToken) =>
            {
                await Task.Delay(TimeSpan.FromSeconds(30), cancellationToken);
                return Array.Empty<SubdomainDiscoveryEntry>();
            }
        };
        var method = typeof(CertificateInventoryCapture).GetMethod(
            "BackfillMissingCtCertificateMetadataExactAsync",
            BindingFlags.NonPublic | BindingFlags.Instance);

        Assert.NotNull(method);

        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        var warnings = new List<string>();
        var diagnostics = new List<PassiveCtDiagnosticEntry>();
        var options = new CertificateInventoryCaptureOptions
        {
            EnablePassiveCtFallback = true,
            EnablePassiveCtMetadataFallback = true
        };

        Task<IReadOnlyList<SubdomainDiscoveryEntry>> task =
            (Task<IReadOnlyList<SubdomainDiscoveryEntry>>)method!.Invoke(
                capture,
                new object[]
                {
                    new[] { "api.example.com" },
                    options,
                    warnings,
                    diagnostics,
                    new InternalLogger(false),
                    cts.Token
                })!;

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await task);
    }

    [Theory]
    [InlineData(16, 4, 2, 40, true, 4)]
    [InlineData(3, 8, 2, 40, true, 3)]
    [InlineData(16, 4, 2, 5, true, 4)]
    [InlineData(16, 4, 2, 3, true, 3)]
    [InlineData(16, 4, 2, 40, false, 2)]
    [InlineData(16, 4, 5, 40, false, 5)]
    [InlineData(3, 8, 2, 40, false, 2)]
    public void ResolveExactPassiveCtMetadataBackfillParallelism_UsesBoundedConcurrency(
        int configuredDiscoveryParallelism,
        int configuredPassiveCtParallelism,
        int configuredCrtShPostgreSqlMaximumConcurrentRequests,
        int hostCount,
        bool usePassiveNetworkQueries,
        int expected)
    {
        int result = CertificateInventoryCapture.ResolveExactPassiveCtMetadataBackfillParallelism(
            configuredDiscoveryParallelism,
            configuredPassiveCtParallelism,
            configuredCrtShPostgreSqlMaximumConcurrentRequests,
            hostCount,
            usePassiveNetworkQueries);

        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData(16, 4, 40, 4)]
    [InlineData(3, 8, 40, 3)]
    [InlineData(16, 4, 3, 3)]
    public void ResolvePassiveCtNetworkParallelism_UsesPassiveSpecificCap(
        int configuredDiscoveryParallelism,
        int configuredPassiveCtParallelism,
        int workItemCount,
        int expected)
    {
        int result = CertificateInventoryCapture.ResolvePassiveCtNetworkParallelism(
            configuredDiscoveryParallelism,
            configuredPassiveCtParallelism,
            workItemCount);

        Assert.Equal(expected, result);
    }

    [Fact]
    public void BuildExactPassiveCtMetadataCandidateHosts_AdmitsTargetedNonSeedHostsAndSkipsHydratedOrSuppressedEntries()
    {
        var existingEntries = new Dictionary<string, SubdomainDiscoveryEntry>(StringComparer.OrdinalIgnoreCase)
        {
            ["hydrated.example.com"] = new()
            {
                Name = "hydrated.example.com",
                LatestCertificateSubject = "CN=hydrated.example.com"
            }
        };
        var suppressedHosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "suppressed.example.com"
        };

        IReadOnlyList<string> result = CertificateInventoryCapture.BuildExactPassiveCtMetadataCandidateHosts(
            new[] { "seed.example.com", "hydrated.example.com" },
            new[] { "api.example.com", "suppressed.example.com", "seed.example.com" },
            suppressedHosts,
            existingEntries);

        Assert.Equal(
            new[]
            {
                "api.example.com",
                "seed.example.com"
            },
            result);
    }

    [Theory]
    [InlineData(true, true, DnsEndpoint.Quad9, 0, false, true)]
    [InlineData(true, true, DnsEndpoint.Quad9, 0, true, false)]
    [InlineData(true, true, DnsEndpoint.System, 0, false, false)]
    [InlineData(true, false, DnsEndpoint.Quad9, 0, false, false)]
    [InlineData(true, true, DnsEndpoint.Quad9, 3, false, false)]
    [InlineData(false, true, DnsEndpoint.Quad9, 0, false, false)]
    public void ShouldRetryPassiveCtVerificationOnSystemDns_OnlyRetriesWhenDnsIsTheLikelyProblem(
        bool allowSystemDnsRetry,
        bool verifyCtDiscoveredSubdomains,
        DnsEndpoint effectiveDnsEndpoint,
        int discoveredCount,
        bool passiveRunSuppressed,
        bool expected)
    {
        bool result = CertificateInventoryCapture.ShouldRetryPassiveCtVerificationOnSystemDns(
            allowSystemDnsRetry,
            verifyCtDiscoveredSubdomains,
            effectiveDnsEndpoint,
            discoveredCount,
            passiveRunSuppressed);

        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData("Passive CT source 'crt.sh' is cooling down until 2026-03-20 09:39:41Z; check later or let the next run retry.", true, "source:crt.sh:cooldown")]
    [InlineData("Passive CT source 'certspotter' is temporarily unavailable: HTTP 429 Too Many Requests (Retry-After 578s). Next retry after 2026-03-20 09:48:50Z.", true, "source:certspotter:unavailable")]
    [InlineData("Passive CT sources were temporarily unavailable or rate-limited; check later or let the next monitoring cycle retry.", true, "sources:shared-unavailable")]
    [InlineData("CT subdomain discovery failed for example.com: timeout", false, "")]
    public void TryNormalizePassiveCtRunLevelWarning_ClassifiesSharedProviderWarnings(
        string warning,
        bool expected,
        string expectedKey)
    {
        bool result = CertificateInventoryCapture.TryNormalizePassiveCtRunLevelWarning(
            warning,
            out string normalizedKey);

        Assert.Equal(expected, result);
        Assert.Equal(expectedKey, normalizedKey);
    }

    [Fact]
    public void FormatPassiveCtWarningForCaptureRun_DeduplicatesRunLevelWarningsButKeepsDomainContext()
    {
        var emittedRunLevelWarnings = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        const string runLevelWarning = "Passive CT source 'crt.sh' is cooling down until 2026-03-20 09:39:41Z; check later or let the next run retry.";
        const string domainSpecificWarning = "Results were capped for this domain.";

        string? firstRunLevelWarning = CertificateInventoryCapture.FormatPassiveCtWarningForCaptureRun(
            "api.example.com",
            runLevelWarning,
            emittedRunLevelWarnings);
        string? duplicateRunLevelWarning = CertificateInventoryCapture.FormatPassiveCtWarningForCaptureRun(
            "www.example.com",
            runLevelWarning,
            emittedRunLevelWarnings);
        string? domainScopedWarning = CertificateInventoryCapture.FormatPassiveCtWarningForCaptureRun(
            "portal.example.com",
            domainSpecificWarning,
            emittedRunLevelWarnings);

        Assert.Equal(runLevelWarning, firstRunLevelWarning);
        Assert.Null(duplicateRunLevelWarning);
        Assert.Equal(
            "Passive CT fallback for portal.example.com: Results were capped for this domain.",
            domainScopedWarning);
    }

    [Fact]
    public void CanPersistPassiveCtExactNoRowsDiagnostic_RequiresCleanSuccessfulQuery()
    {
        var succeeded = new PassiveCtSourceClient.QueryResult();
        succeeded.Diagnostics.Add(new PassiveCtDiagnosticEntry
        {
            SourceName = "crt.sh",
            State = "Succeeded"
        });

        var rateLimited = new PassiveCtSourceClient.QueryResult
        {
            RetrySuggested = true
        };
        rateLimited.Diagnostics.Add(new PassiveCtDiagnosticEntry
        {
            SourceName = "certspotter",
            State = "RateLimited",
            RetrySuggested = true
        });

        Assert.True(CertificateInventoryCapture.CanPersistPassiveCtExactNoRowsDiagnostic(succeeded));
        Assert.False(CertificateInventoryCapture.CanPersistPassiveCtExactNoRowsDiagnostic(rateLimited));
        Assert.False(CertificateInventoryCapture.CanPersistPassiveCtExactNoRowsDiagnostic(null));
    }

    [Fact]
    public void AppendPassiveCtExactNoRowsDiagnostics_RecordsDistinctExactHostNoRowSignals()
    {
        var diagnostics = new List<PassiveCtDiagnosticEntry>();

        CertificateInventoryCapture.AppendPassiveCtExactNoRowsDiagnostics(
            "api.example.com",
            new[]
            {
                new PassiveCtSourceClient.SourceRequest
                {
                    SourceName = "crt.sh",
                    Url = "https://crt.sh/?q=api.example.com&output=json"
                },
                new PassiveCtSourceClient.SourceRequest
                {
                    SourceName = "crt.sh",
                    Url = "https://crt.sh/?q=api.example.com&output=json"
                },
                new PassiveCtSourceClient.SourceRequest
                {
                    SourceName = "certspotter",
                    Url = "https://api.certspotter.com/v1/issuances?domain=api.example.com"
                }
            },
            diagnostics);

        Assert.Collection(
            diagnostics,
            row =>
            {
                Assert.Equal("api.example.com", row.Scope);
                Assert.Equal("MetadataExact", row.QueryKind);
                Assert.Equal("crt.sh", row.SourceName);
                Assert.Equal("NoRows", row.State);
            },
            row =>
            {
                Assert.Equal("api.example.com", row.Scope);
                Assert.Equal("MetadataExact", row.QueryKind);
                Assert.Equal("certspotter", row.SourceName);
                Assert.Equal("NoRows", row.State);
            });
    }

    [Fact]
    public async Task ExactCtMetadataBackfill_SkipsWhenRestoredSharedPassiveCooldownsAreStillActive()
    {
        PassiveCtSourceClient.ResetSharedStateForTesting();
        try
        {
            CertificateInventoryCapture.RestorePassiveCtSharedCooldownState(
                new[]
                {
                    new PassiveCtDiagnosticEntry
                    {
                        SourceName = "crt.sh",
                        State = "RateLimited",
                        RetrySuggested = true,
                        CooldownUntilUtc = DateTimeOffset.UtcNow.AddMinutes(2)
                    },
                    new PassiveCtDiagnosticEntry
                    {
                        SourceName = "certspotter",
                        State = "CoolingDown",
                        RetrySuggested = true,
                        CooldownUntilUtc = DateTimeOffset.UtcNow.AddMinutes(5)
                    }
                });

            var capture = new CertificateInventoryCapture
            {
                CtPassiveMetadataBackfillOverride = (_, _, _, _) =>
                    throw new InvalidOperationException("Passive CT exact metadata query should have been suppressed from restored shared cooldown state.")
            };
            var method = typeof(CertificateInventoryCapture).GetMethod(
                "BackfillMissingCtCertificateMetadataExactAsync",
                BindingFlags.NonPublic | BindingFlags.Instance);

            Assert.NotNull(method);

            var warnings = new List<string>();
            var options = new CertificateInventoryCaptureOptions
            {
                EnablePassiveCtFallback = true,
                EnablePassiveCtMetadataFallback = true
            };

            Task<IReadOnlyList<SubdomainDiscoveryEntry>> task =
                (Task<IReadOnlyList<SubdomainDiscoveryEntry>>)method!.Invoke(
                    capture,
                    new object[]
                    {
                        new[] { "api.example.com", "portal.example.com" },
                        options,
                        warnings,
                        new List<PassiveCtDiagnosticEntry>(),
                        new InternalLogger(false),
                        CancellationToken.None
                    })!;

            IReadOnlyList<SubdomainDiscoveryEntry> result = await task;

            Assert.Empty(result);
            Assert.Contains(
                warnings,
                warning => warning.Contains("Passive CT exact metadata backfill skipped", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            PassiveCtSourceClient.ResetSharedStateForTesting();
        }
    }

    [Fact]
    public async Task BackfillMissingCtCertificateMetadataAsync_RetainsExactPassiveFallbackWhenDomainPostgreSqlLookupFails()
    {
        var verboseMessages = new List<string>();
        var overrideBatches = new List<IReadOnlyList<string>>();
        var capture = new CertificateInventoryCapture
        {
            CtPassiveMetadataBackfillOverride = (hosts, _, _, _) =>
            {
                overrideBatches.Add(hosts.ToList());

                if (hosts.Count == 1 &&
                    string.Equals(hosts[0], "api.example.com", StringComparison.OrdinalIgnoreCase))
                {
                    return Task.FromResult<IReadOnlyList<SubdomainDiscoveryEntry>>(
                    [
                        new SubdomainDiscoveryEntry
                        {
                            Name = "api.example.com",
                            LatestCertificateThumbprint = "EXACT-FALLBACK-THUMBPRINT-001",
                            LatestCertificateSubjectAlternativeNames = new[] { "api.example.com" },
                            CtSources = new[] { "crt.sh" }
                        }
                    ]);
                }

                return Task.FromResult<IReadOnlyList<SubdomainDiscoveryEntry>>(Array.Empty<SubdomainDiscoveryEntry>());
            },
            CtExactMetadataPostgreSqlOverride = static (_, _, _, _) =>
                Task.FromResult<SubdomainDiscoveryEntry?>(null)
        };

        var method = typeof(CertificateInventoryCapture).GetMethod(
            "BackfillMissingCtCertificateMetadataAsync",
            BindingFlags.NonPublic | BindingFlags.Instance);

        Assert.NotNull(method);

        var warnings = new List<string>();
        var options = new CertificateInventoryCaptureOptions
        {
            EnablePassiveCtFallback = true,
            EnablePassiveCtMetadataFallback = true,
            EnableCrtShPostgreSqlMetadataFallback = true,
            CrtShPostgreSqlConnectionString = "Host=127.0.0.1;Port=1;Database=certwatch;Username=guest;SSL Mode=Disable;Timeout=1;Command Timeout=1",
            CrtShPostgreSqlCommandTimeoutSeconds = 1,
            CrtShPostgreSqlMaximumConcurrentRequests = 1
        };
        options.ExactHostSeedCtMetadataSuppressedHosts.Add("api.example.com");

        var logger = new InternalLogger(false);
        logger.OnVerboseMessage += (_, args) =>
        {
            if (!string.IsNullOrWhiteSpace(args.Message))
            {
                verboseMessages.Add(args.Message);
            }
        };

        Task<IReadOnlyList<SubdomainDiscoveryEntry>> task =
            (Task<IReadOnlyList<SubdomainDiscoveryEntry>>)method!.Invoke(
                capture,
                new object[]
                {
                    new[] { "example.com" },
                    new[]
                    {
                        new SubdomainDiscoveryEntry
                        {
                            Name = "api.example.com"
                        }
                    },
                    options,
                    warnings,
                    new List<PassiveCtDiagnosticEntry>(),
                    logger,
                    CancellationToken.None
                })!;

        IReadOnlyList<SubdomainDiscoveryEntry> result = await task;

        SubdomainDiscoveryEntry entry = Assert.Single(result);
        Assert.Equal("api.example.com", entry.Name);
        Assert.Equal("EXACT-FALLBACK-THUMBPRINT-001", entry.LatestCertificateThumbprint);
        Assert.Contains(
            overrideBatches,
            hosts => hosts.Count == 1 &&
                     string.Equals(hosts[0], "example.com", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(
            overrideBatches,
            hosts => hosts.Count == 1 &&
                     string.Equals(hosts[0], "api.example.com", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(
            verboseMessages,
            message => message.Contains("retaining 1 remaining host(s) for exact passive CT metadata", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(
            verboseMessages,
            message => message.Contains("skipping exact passive CT metadata", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task BackfillMissingCtCertificateMetadataAsync_UsesExactPostgreSqlProviderWhenDomainProviderIsUnavailable()
    {
        var capture = new CertificateInventoryCapture
        {
            CtPassiveMetadataBackfillOverride = (_, _, _, _) =>
                throw new InvalidOperationException("Passive CT exact metadata query should not run when exact PostgreSQL metadata hydrates the host."),
            CtExactMetadataPostgreSqlOverride = (host, _, _, _) =>
            {
                if (!string.Equals(host, "api.example.com", StringComparison.OrdinalIgnoreCase))
                {
                    return Task.FromResult<SubdomainDiscoveryEntry?>(null);
                }

                return Task.FromResult<SubdomainDiscoveryEntry?>(
                    new SubdomainDiscoveryEntry
                    {
                        Name = "api.example.com",
                        LatestCertificateThumbprint = "EXACT-SQL-THUMBPRINT-001",
                        LatestCertificateSubjectAlternativeNames = new[] { "api.example.com" },
                        CtSources = new[] { "crt.sh-db" }
                    });
            }
        };

        var method = typeof(CertificateInventoryCapture).GetMethod(
            "BackfillMissingCtCertificateMetadataAsync",
            BindingFlags.NonPublic | BindingFlags.Instance);

        Assert.NotNull(method);

        var warnings = new List<string>();
        var options = new CertificateInventoryCaptureOptions
        {
            EnablePassiveCtFallback = false,
            EnablePassiveCtMetadataFallback = false,
            EnableCrtShPostgreSqlMetadataFallback = true,
            BackfillMissingCtCertificateMetadata = true
        };

        Task<IReadOnlyList<SubdomainDiscoveryEntry>> task =
            (Task<IReadOnlyList<SubdomainDiscoveryEntry>>)method!.Invoke(
                capture,
                new object[]
                {
                    new[] { "example.com" },
                    new[]
                    {
                        new SubdomainDiscoveryEntry
                        {
                            Name = "api.example.com"
                        }
                    },
                    options,
                    warnings,
                    new List<PassiveCtDiagnosticEntry>(),
                    new InternalLogger(false),
                    CancellationToken.None
                })!;

        IReadOnlyList<SubdomainDiscoveryEntry> result = await task;

        SubdomainDiscoveryEntry entry = Assert.Single(result);
        Assert.Equal("api.example.com", entry.Name);
        Assert.Equal("EXACT-SQL-THUMBPRINT-001", entry.LatestCertificateThumbprint);
        Assert.Empty(warnings);
    }

    [Fact]
    public async Task BackfillMissingCtCertificateMetadataAsync_SkipsPostgreSqlProviderWhenFallbackDisabled()
    {
        int exactPostgreSqlLookupCount = 0;
        var capture = new CertificateInventoryCapture
        {
            CtExactMetadataPostgreSqlOverride = (host, _, _, _) =>
            {
                exactPostgreSqlLookupCount++;
                return Task.FromResult<SubdomainDiscoveryEntry?>(
                    new SubdomainDiscoveryEntry
                    {
                        Name = host,
                        LatestCertificateThumbprint = "SHOULD-NOT-BE-USED"
                    });
            }
        };

        var method = typeof(CertificateInventoryCapture).GetMethod(
            "BackfillMissingCtCertificateMetadataAsync",
            BindingFlags.NonPublic | BindingFlags.Instance);

        Assert.NotNull(method);

        var warnings = new List<string>();
        var options = new CertificateInventoryCaptureOptions
        {
            EnablePassiveCtFallback = false,
            EnablePassiveCtMetadataFallback = false,
            EnableCrtShPostgreSqlMetadataFallback = false,
            BackfillMissingCtCertificateMetadata = true
        };

        Task<IReadOnlyList<SubdomainDiscoveryEntry>> task =
            (Task<IReadOnlyList<SubdomainDiscoveryEntry>>)method!.Invoke(
                capture,
                new object[]
                {
                    new[] { "example.com" },
                    new[]
                    {
                        new SubdomainDiscoveryEntry
                        {
                            Name = "api.example.com"
                        }
                    },
                    options,
                    warnings,
                    new List<PassiveCtDiagnosticEntry>(),
                    new InternalLogger(false),
                    CancellationToken.None
                })!;

        IReadOnlyList<SubdomainDiscoveryEntry> result = await task;

        SubdomainDiscoveryEntry entry = Assert.Single(result);
        Assert.Equal("api.example.com", entry.Name);
        Assert.Null(entry.LatestCertificateThumbprint);
        Assert.Equal(0, exactPostgreSqlLookupCount);
        Assert.Empty(warnings);
    }

    [Fact]
    public async Task CaptureAsync_DoesNotAnnounceExactPassiveMetadataQueryWhenSharedCooldownAlreadyBlocksRun()
    {
        PassiveCtSourceClient.ResetSharedStateForTesting();
        try
        {
            CertificateInventoryCapture.RestorePassiveCtSharedCooldownState(
                new[]
                {
                    new PassiveCtDiagnosticEntry
                    {
                        SourceName = "crt.sh",
                        State = "CoolingDown",
                        RetrySuggested = true,
                        CooldownUntilUtc = DateTimeOffset.UtcNow.AddMinutes(2)
                    },
                    new PassiveCtDiagnosticEntry
                    {
                        SourceName = "certspotter",
                        State = "CoolingDown",
                        RetrySuggested = true,
                        CooldownUntilUtc = DateTimeOffset.UtcNow.AddMinutes(5)
                    }
                });

            var verboseMessages = new List<string>();
            var capture = new CertificateInventoryCapture
            {
                HttpsProbeOverride = (_, _, _, _) => Task.FromResult<IReadOnlyList<CertificateMonitor.Entry>>(Array.Empty<CertificateMonitor.Entry>()),
                CtPassiveMetadataBackfillOverride = (_, _, _, _) =>
                    throw new InvalidOperationException("Passive CT exact metadata query should not start when the shared cooldown already blocks the run.")
            };

            var options = new CertificateInventoryCaptureOptions
            {
                IncludeApexHttps = false,
                IncludeWwwHttps = false,
                IncludeCtDiscoveredSubdomains = false,
                VerifyCtDiscoveredSubdomains = false,
                IncludeMxHosts = false,
                IncludeMxHttps = false,
                IncludeSmtpStartTls = false,
                IncludeSubmissionStartTls = false,
                IncludeImapTls = false,
                IncludePop3Tls = false,
                EnablePassiveCtFallback = true,
                EnablePassiveCtMetadataFallback = true,
                BackfillMissingCtCertificateMetadata = true,
                PersistSnapshot = false
            };

            var logger = new InternalLogger(false);
            logger.OnVerboseMessage += (_, args) =>
            {
                if (!string.IsNullOrWhiteSpace(args.Message))
                {
                    verboseMessages.Add(args.Message);
                }
            };

            CertificateInventoryCaptureResult result = await capture.CaptureAsync(
                new[] { "airtoxics.eurofins.com" },
                options,
                logger,
                CancellationToken.None);

            Assert.NotNull(result);
            Assert.DoesNotContain(
                verboseMessages,
                message => message.Contains("CT metadata backfill: querying exact passive CT metadata", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(
                verboseMessages,
                message => message.Contains("Passive CT exact metadata backfill skipped", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            PassiveCtSourceClient.ResetSharedStateForTesting();
        }
    }

    [Fact]
    public async Task CaptureAsync_SkipsExactHostSeedMetadataBackfillForSuppressedHosts()
    {
        var verboseMessages = new List<string>();
        var capture = new CertificateInventoryCapture
        {
            HttpsProbeOverride = (_, _, _, _) => Task.FromResult<IReadOnlyList<CertificateMonitor.Entry>>(Array.Empty<CertificateMonitor.Entry>()),
            CtPassiveMetadataBackfillOverride = (_, _, _, _) =>
                throw new InvalidOperationException("Suppressed exact-host seed should not trigger passive CT metadata rescue.")
        };

        var options = new CertificateInventoryCaptureOptions
        {
            IncludeApexHttps = false,
            IncludeWwwHttps = false,
            IncludeCtDiscoveredSubdomains = false,
            VerifyCtDiscoveredSubdomains = false,
            IncludeMxHosts = false,
            IncludeMxHttps = false,
            IncludeSmtpStartTls = false,
            IncludeSubmissionStartTls = false,
            IncludeImapTls = false,
            IncludePop3Tls = false,
            EnablePassiveCtFallback = true,
            EnablePassiveCtMetadataFallback = true,
            BackfillMissingCtCertificateMetadata = true,
            PersistSnapshot = false
        };
        options.ExactHostSeedCtMetadataSuppressedHosts.Add("airtoxics.eurofins.com");

        var logger = new InternalLogger(false);
        logger.OnVerboseMessage += (_, args) =>
        {
            if (!string.IsNullOrWhiteSpace(args.Message))
            {
                verboseMessages.Add(args.Message);
            }
        };

        CertificateInventoryCaptureResult result = await capture.CaptureAsync(
            new[] { "airtoxics.eurofins.com" },
            options,
            logger,
            CancellationToken.None);

        Assert.NotNull(result);
        Assert.DoesNotContain(
            verboseMessages,
            message => message.Contains("CT metadata backfill: querying exact passive CT metadata", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task CaptureAsync_TargetedCtMetadataHosts_LimitsExactHostSeedMetadataBackfill()
    {
        PassiveCtSourceClient.ResetSharedStateForTesting();
        try
        {
            IReadOnlyList<string>? requestedHosts = null;
            var capture = new CertificateInventoryCapture
            {
                HttpsProbeOverride = (_, _, _, _) => Task.FromResult<IReadOnlyList<CertificateMonitor.Entry>>(Array.Empty<CertificateMonitor.Entry>()),
                CtPassiveMetadataBackfillOverride = (hosts, _, _, _) =>
                {
                    requestedHosts = hosts.ToList();
                    return Task.FromResult<IReadOnlyList<SubdomainDiscoveryEntry>>(Array.Empty<SubdomainDiscoveryEntry>());
                }
            };

            var options = new CertificateInventoryCaptureOptions
            {
                IncludeApexHttps = false,
                IncludeWwwHttps = false,
                IncludeCtDiscoveredSubdomains = false,
                VerifyCtDiscoveredSubdomains = false,
                IncludeMxHosts = false,
                IncludeMxHttps = false,
                IncludeSmtpStartTls = false,
                IncludeSubmissionStartTls = false,
                IncludeImapTls = false,
                IncludePop3Tls = false,
                EnablePassiveCtFallback = false,
                EnablePassiveCtMetadataFallback = true,
                BackfillMissingCtCertificateMetadata = true,
                PersistSnapshot = false
            };
            options.CtMetadataTargetHosts.Add("api.example.com");

            CertificateInventoryCaptureResult result = await capture.CaptureAsync(
                new[] { "api.example.com", "portal.example.com" },
                options,
                cancellationToken: CancellationToken.None);

            Assert.NotNull(result);
            Assert.NotNull(requestedHosts);
            Assert.Equal(new[] { "api.example.com" }, requestedHosts);
        }
        finally
        {
            PassiveCtSourceClient.ResetSharedStateForTesting();
        }
    }

    [Fact]
    public async Task CaptureAsync_ExactPassiveCtMetadataTargetHosts_OverridesBroaderCtProbeTargets()
    {
        PassiveCtSourceClient.ResetSharedStateForTesting();
        try
        {
            IReadOnlyList<string>? requestedHosts = null;
            var capture = new CertificateInventoryCapture
            {
                HttpsProbeOverride = (_, _, _, _) => Task.FromResult<IReadOnlyList<CertificateMonitor.Entry>>(Array.Empty<CertificateMonitor.Entry>()),
                CtPassiveMetadataBackfillOverride = (hosts, _, _, _) =>
                {
                    requestedHosts = hosts.ToList();
                    return Task.FromResult<IReadOnlyList<SubdomainDiscoveryEntry>>(Array.Empty<SubdomainDiscoveryEntry>());
                }
            };

            var options = new CertificateInventoryCaptureOptions
            {
                IncludeApexHttps = false,
                IncludeWwwHttps = false,
                IncludeCtDiscoveredSubdomains = false,
                VerifyCtDiscoveredSubdomains = false,
                IncludeMxHosts = false,
                IncludeMxHttps = false,
                IncludeSmtpStartTls = false,
                IncludeSubmissionStartTls = false,
                IncludeImapTls = false,
                IncludePop3Tls = false,
                EnablePassiveCtFallback = false,
                EnablePassiveCtMetadataFallback = true,
                BackfillMissingCtCertificateMetadata = true,
                PersistSnapshot = false
            };
            options.CtMetadataTargetHosts.Add("portal.example.com");
            options.ExactPassiveCtMetadataTargetHosts.Add("api.example.com");

            CertificateInventoryCaptureResult result = await capture.CaptureAsync(
                new[] { "api.example.com", "portal.example.com" },
                options,
                cancellationToken: CancellationToken.None);

            Assert.NotNull(result);
            Assert.NotNull(requestedHosts);
            Assert.Equal(new[] { "api.example.com" }, requestedHosts);
        }
        finally
        {
            PassiveCtSourceClient.ResetSharedStateForTesting();
        }
    }

    [Fact]
    public async Task BackfillMissingCtCertificateMetadataAsync_SkipsSuppressedRemainingHosts()
    {
        var verboseMessages = new List<string>();
        var capture = new CertificateInventoryCapture
        {
            CtPassiveMetadataBackfillOverride = (requestedHosts, _, _, _) =>
            {
                if (requestedHosts.Count == 1 &&
                    string.Equals(requestedHosts[0], "eurofins.com", StringComparison.OrdinalIgnoreCase))
                {
                    return Task.FromResult<IReadOnlyList<SubdomainDiscoveryEntry>>(Array.Empty<SubdomainDiscoveryEntry>());
                }

                throw new InvalidOperationException("Suppressed remaining host should not trigger passive CT metadata rescue.");
            }
        };

        var method = typeof(CertificateInventoryCapture).GetMethod(
            "BackfillMissingCtCertificateMetadataAsync",
            BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.NotNull(method);

        var options = new CertificateInventoryCaptureOptions
        {
            EnablePassiveCtFallback = true,
            EnablePassiveCtMetadataFallback = true,
            BackfillMissingCtCertificateMetadata = true
        };
        options.ExactHostSeedCtMetadataSuppressedHosts.Add("airtoxics.eurofins.com");

        var logger = new InternalLogger(false);
        logger.OnVerboseMessage += (_, args) =>
        {
            if (!string.IsNullOrWhiteSpace(args.Message))
            {
                verboseMessages.Add(args.Message);
            }
        };

        Task<IReadOnlyList<SubdomainDiscoveryEntry>> task =
            (Task<IReadOnlyList<SubdomainDiscoveryEntry>>)method!.Invoke(
                capture,
                new object[]
                {
                    new[] { "eurofins.com" },
                    new[]
                    {
                        new SubdomainDiscoveryEntry
                        {
                            Name = "airtoxics.eurofins.com",
                            ResolutionStatus = SubdomainResolutionStatus.Unknown
                        }
                    },
                    options,
                    new List<string>(),
                    new List<PassiveCtDiagnosticEntry>(),
                    logger,
                    CancellationToken.None
                })!;

        IReadOnlyList<SubdomainDiscoveryEntry> result = await task;

        Assert.Single(result);
        Assert.Equal("airtoxics.eurofins.com", result[0].Name);
        Assert.DoesNotContain(
            verboseMessages,
            message => message.Contains("CT metadata backfill: querying exact passive CT metadata", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(
            verboseMessages,
            message => message.Contains("skipping exact passive CT metadata", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ApplyCtDiscoveryOnlyProfile_DisablesProbeExpansionAndKeepsCtDiscoveryEnabled()
    {
        var options = new CertificateInventoryCaptureOptions
        {
            IncludeApexHttps = true,
            IncludeWwwHttps = true,
            IncludeCtDiscoveredSubdomains = false,
            EnableNativeCtLogSubdomainSource = false,
            EnablePassiveCtFallback = false,
            NativeCtLogOnly = true,
            VerifyCtDiscoveredSubdomains = true,
            BackfillMissingCtCertificateMetadata = false,
            PromoteCtDiscoveredSubdomainsToHttpsProbes = true,
            IncludeMxHosts = true,
            IncludeMxHttps = true,
            IncludeSmtpStartTls = true,
            IncludeSubmissionStartTls = true,
            IncludeImapTls = true,
            IncludePop3Tls = true
        };

        CertificateInventoryCaptureOptions returned = options.ApplyCtDiscoveryOnlyProfile();

        Assert.Same(options, returned);
        Assert.False(options.IncludeApexHttps);
        Assert.False(options.IncludeWwwHttps);
        Assert.True(options.IncludeCtDiscoveredSubdomains);
        Assert.True(options.EnableNativeCtLogSubdomainSource);
        Assert.True(options.EnablePassiveCtFallback);
        Assert.False(options.NativeCtLogOnly);
        Assert.False(options.VerifyCtDiscoveredSubdomains);
        Assert.True(options.BackfillMissingCtCertificateMetadata);
        Assert.False(options.PromoteCtDiscoveredSubdomainsToHttpsProbes);
        Assert.False(options.IncludeMxHosts);
        Assert.False(options.IncludeMxHttps);
        Assert.False(options.IncludeSmtpStartTls);
        Assert.False(options.IncludeSubmissionStartTls);
        Assert.False(options.IncludeImapTls);
        Assert.False(options.IncludePop3Tls);
    }

    [Fact]
    public void ApplyCtEvidenceRefreshProfile_DisablesCtDiscoveryAndMailExpansion()
    {
        var options = new CertificateInventoryCaptureOptions
        {
            IncludeApexHttps = false,
            IncludeWwwHttps = true,
            IncludeCtDiscoveredSubdomains = true,
            EnableNativeCtLogSubdomainSource = true,
            EnablePassiveCtFallback = true,
            EnablePassiveCtMetadataFallback = false,
            NativeCtLogOnly = true,
            VerifyCtDiscoveredSubdomains = true,
            BackfillMissingCtCertificateMetadata = false,
            PromoteCtDiscoveredSubdomainsToHttpsProbes = true,
            IncludeMxHosts = true,
            IncludeMxHttps = true,
            IncludeSmtpStartTls = true,
            IncludeSubmissionStartTls = true,
            IncludeImapTls = true,
            IncludePop3Tls = true
        };

        CertificateInventoryCaptureOptions returned = options.ApplyCtEvidenceRefreshProfile();

        Assert.Same(options, returned);
        Assert.True(options.IncludeApexHttps);
        Assert.False(options.IncludeWwwHttps);
        Assert.False(options.IncludeCtDiscoveredSubdomains);
        Assert.False(options.EnableNativeCtLogSubdomainSource);
        Assert.False(options.EnablePassiveCtFallback);
        Assert.True(options.EnablePassiveCtMetadataFallback);
        Assert.False(options.NativeCtLogOnly);
        Assert.False(options.VerifyCtDiscoveredSubdomains);
        Assert.True(options.BackfillMissingCtCertificateMetadata);
        Assert.False(options.PromoteCtDiscoveredSubdomainsToHttpsProbes);
        Assert.False(options.IncludeMxHosts);
        Assert.False(options.IncludeMxHttps);
        Assert.False(options.IncludeSmtpStartTls);
        Assert.False(options.IncludeSubmissionStartTls);
        Assert.False(options.IncludeImapTls);
        Assert.False(options.IncludePop3Tls);
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
        return CertificateLoaderCompat.LoadCertificate(certificate.Export(X509ContentType.Cert));
    }

    private static void InvokeCtMetadataEnrichment(
        CertificateInventoryEntry entry,
        IReadOnlyDictionary<string, SubdomainDiscoveryEntry> discoveredEntries) {
        var method = typeof(CertificateInventoryCapture).GetMethod(
            "EnrichEntriesWithCtSubdomainMetadata",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        method!.Invoke(
            null,
            new object[] {
                new[] { entry },
                discoveredEntries,
                DateTimeOffset.UtcNow
            });
    }
}

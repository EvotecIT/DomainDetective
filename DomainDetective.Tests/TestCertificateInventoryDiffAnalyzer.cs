using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Tests {
    public class TestCertificateInventoryDiffAnalyzer {
        [Fact]
        public void BuildDiffClassifiesAddedRemovedChangedAndUnchangedEndpoints() {
            var now = DateTimeOffset.UtcNow;
            var previous = new CertificateInventorySnapshot {
                CapturedAtUtc = now.AddHours(-2),
                Port = 443,
                Entries = new List<CertificateInventoryEntry> {
                    new() {
                        Host = "api.example.com",
                        ResolvedHost = "api.example.com",
                        Port = 443,
                        Service = "HTTPS",
                        CertificateThumbprint = "AAA111",
                        CertificateIssuerNormalized = "Issuer A",
                        CertificateRootIssuerNormalized = "Root A",
                        NotAfterUtc = now.AddDays(20),
                        Valid = true,
                        ChainComplete = true,
                        HostnameMatch = true
                    },
                    new() {
                        Host = "legacy.example.com",
                        ResolvedHost = "legacy.example.com",
                        Port = 443,
                        Service = "HTTPS",
                        CertificateThumbprint = "LEGACY1",
                        CertificateIssuerNormalized = "Issuer Legacy",
                        NotAfterUtc = now.AddDays(10),
                        Valid = true
                    },
                    new() {
                        Host = "portal.example.com",
                        ResolvedHost = "portal.example.com",
                        Port = 8443,
                        Service = "HTTPS-Alt",
                        CertificateThumbprint = "STABLE1",
                        CertificateIssuerNormalized = "Issuer Stable",
                        NotAfterUtc = now.AddDays(40),
                        Valid = true
                    }
                }
            };
            var current = new CertificateInventorySnapshot {
                CapturedAtUtc = now,
                Port = 443,
                Entries = new List<CertificateInventoryEntry> {
                    new() {
                        Host = "api.example.com",
                        ResolvedHost = "api.example.com",
                        Port = 443,
                        Service = "HTTPS",
                        CertificateThumbprint = "BBB222",
                        CertificateIssuerNormalized = "Issuer B",
                        CertificateRootIssuerNormalized = "Root B",
                        NotAfterUtc = now.AddDays(120),
                        Valid = false,
                        ChainComplete = false,
                        HostnameMatch = false
                    },
                    new() {
                        Host = "portal.example.com",
                        ResolvedHost = "portal.example.com",
                        Port = 8443,
                        Service = "HTTPS-Alt",
                        CertificateThumbprint = "STABLE1",
                        CertificateIssuerNormalized = "Issuer Stable",
                        NotAfterUtc = now.AddDays(40),
                        Valid = true
                    },
                    new() {
                        Host = "new.example.com",
                        ResolvedHost = "new.example.com",
                        Port = 443,
                        Service = "HTTPS",
                        CertificateThumbprint = "NEW333",
                        CertificateIssuerNormalized = "Issuer New",
                        NotAfterUtc = now.AddDays(90),
                        Valid = true
                    }
                }
            };

            var diff = CertificateInventoryDiffAnalyzer.BuildDiff(new[] { previous, current });

            Assert.Null(diff.RequestedPreviousCapturedAtUtc);
            Assert.Null(diff.RequestedCurrentCapturedAtUtc);
            Assert.Equal(previous.CapturedAtUtc, diff.PreviousCapturedAtUtc);
            Assert.Equal(current.CapturedAtUtc, diff.CurrentCapturedAtUtc);
            Assert.Equal(3, diff.PreviousEndpointCount);
            Assert.Equal(3, diff.CurrentEndpointCount);
            Assert.Equal(1, diff.AddedCount);
            Assert.Equal(1, diff.RemovedCount);
            Assert.Equal(1, diff.ChangedCount);
            Assert.Equal(1, diff.UnchangedCount);
            Assert.Empty(diff.Warnings);

            var api = diff.Endpoints.Single(x => x.Host == "api.example.com");
            Assert.Equal("Changed", api.Status);
            Assert.Contains("Certificate", api.ChangeReasons);
            Assert.Contains("Issuer", api.ChangeReasons);
            Assert.Contains("Root", api.ChangeReasons);
            Assert.Contains("Expiry", api.ChangeReasons);
            Assert.Contains("Valid", api.ChangeReasons);
            Assert.Contains("Chain", api.ChangeReasons);
            Assert.Contains("Hostname", api.ChangeReasons);
            Assert.Equal("AAA111", api.PreviousThumbprint);
            Assert.Equal("BBB222", api.CurrentThumbprint);

            var added = diff.Endpoints.Single(x => x.Host == "new.example.com");
            Assert.Equal("Added", added.Status);
            Assert.Contains("EndpointAdded", added.ChangeReasons);

            var removed = diff.Endpoints.Single(x => x.Host == "legacy.example.com");
            Assert.Equal("Removed", removed.Status);
            Assert.Contains("EndpointRemoved", removed.ChangeReasons);
        }

        [Fact]
        public void BuildDiffCorrelatesUniqueServiceReplacementWithinTransportSlot() {
            var now = DateTimeOffset.UtcNow;
            var previous = new CertificateInventorySnapshot {
                CapturedAtUtc = now.AddHours(-1),
                Entries = new List<CertificateInventoryEntry> {
                    new() {
                        Host = "service-change.example.com",
                        ResolvedHost = "service-change.example.com",
                        Port = 443,
                        Service = "HTTPS",
                        CertificateThumbprint = "SVC-THUMB"
                    }
                }
            };
            var current = new CertificateInventorySnapshot {
                CapturedAtUtc = now,
                Entries = new List<CertificateInventoryEntry> {
                    new() {
                        Host = "service-change.example.com",
                        ResolvedHost = "service-change.example.com",
                        Port = 443,
                        Service = "HTTPS-ALT",
                        CertificateThumbprint = "SVC-THUMB"
                    }
                }
            };

            var diff = CertificateInventoryDiffAnalyzer.BuildDiff(new[] { previous, current });

            Assert.Equal(1, diff.PreviousEndpointCount);
            Assert.Equal(1, diff.CurrentEndpointCount);
            Assert.Equal(0, diff.AddedCount);
            Assert.Equal(0, diff.RemovedCount);
            Assert.Equal(1, diff.ChangedCount);
            Assert.Equal(0, diff.UnchangedCount);

            CertificateInventoryEndpointDiff endpoint = Assert.Single(diff.Endpoints);
            Assert.Equal("service-change.example.com", endpoint.Host);
            Assert.Equal("Changed", endpoint.Status);
            Assert.Equal("HTTPS", endpoint.PreviousService);
            Assert.Equal("HTTPS-ALT", endpoint.CurrentService);
            Assert.Equal(new[] { "Service" }, endpoint.ChangeReasons);
        }

        [Fact]
        public void BuildDiffDoesNotInventAmbiguousServiceReplacement() {
            var now = DateTimeOffset.UtcNow;
            CertificateInventoryEntry Entry(string service) => new() {
                Host = "ambiguous-service.example.com",
                ResolvedHost = "ambiguous-service.example.com",
                Port = 443,
                Service = service,
                CertificateThumbprint = service
            };
            var previous = new CertificateInventorySnapshot {
                CapturedAtUtc = now.AddHours(-1),
                Entries = new List<CertificateInventoryEntry> { Entry("SERVICE-A"), Entry("SERVICE-B") }
            };
            var current = new CertificateInventorySnapshot {
                CapturedAtUtc = now,
                Entries = new List<CertificateInventoryEntry> { Entry("SERVICE-C"), Entry("SERVICE-D") }
            };

            CertificateInventoryDiffSummary diff = CertificateInventoryDiffAnalyzer.BuildDiff(new[] { previous, current });

            Assert.Equal(2, diff.AddedCount);
            Assert.Equal(2, diff.RemovedCount);
            Assert.Equal(0, diff.ChangedCount);
            Assert.Equal(4, diff.Endpoints.Count);
            Assert.DoesNotContain(diff.Endpoints, endpoint => endpoint.ChangeReasons.Contains("Service"));
        }

        [Fact]
        public void BuildDiffKeepsProbeVantageHistoriesSeparate() {
            var now = DateTimeOffset.UtcNow;
            CertificateInventoryEntry Entry(string vantage, string thumbprint) => new() {
                Host = "shared.example.com",
                ResolvedHost = "shared.example.com",
                Port = 443,
                Service = "HTTPS",
                ProbeVantage = vantage,
                CertificateThumbprint = thumbprint
            };
            var previous = new CertificateInventorySnapshot {
                CapturedAtUtc = now.AddHours(-1),
                Entries = new List<CertificateInventoryEntry> {
                    Entry("branch-office", "BRANCH"),
                    Entry("cloud", "CLOUD")
                }
            };
            var current = new CertificateInventorySnapshot {
                CapturedAtUtc = now,
                Entries = new List<CertificateInventoryEntry> {
                    Entry(" cloud ", "CLOUD"),
                    Entry("BRANCH-OFFICE", "BRANCH")
                }
            };

            var diff = CertificateInventoryDiffAnalyzer.BuildDiff(
                new[] { previous, current },
                includeUnchanged: true);

            Assert.Equal(2, diff.PreviousEndpointCount);
            Assert.Equal(2, diff.CurrentEndpointCount);
            Assert.Equal(0, diff.AddedCount);
            Assert.Equal(0, diff.RemovedCount);
            Assert.Equal(0, diff.ChangedCount);
            Assert.Equal(2, diff.UnchangedCount);
            Assert.Collection(
                diff.Endpoints.OrderBy(endpoint => endpoint.ProbeVantage, StringComparer.OrdinalIgnoreCase),
                endpoint => Assert.Equal("branch-office", endpoint.ProbeVantage, ignoreCase: true),
                endpoint => Assert.Equal("cloud", endpoint.ProbeVantage, ignoreCase: true));
        }

        [Fact]
        public void BuildDiffDefaultsToLatestTwoSnapshotsAndCanIncludeUnchanged() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddHours(-3),
                    Entries = new List<CertificateInventoryEntry> {
                        new() { Host = "old.example.com", ResolvedHost = "old.example.com", Port = 443, CertificateThumbprint = "OLD" }
                    }
                },
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddHours(-2),
                    Entries = new List<CertificateInventoryEntry> {
                        new() { Host = "app.example.com", ResolvedHost = "app.example.com", Port = 443, CertificateThumbprint = "A1" }
                    }
                },
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddHours(-1),
                    Entries = new List<CertificateInventoryEntry> {
                        new() { Host = "app.example.com", ResolvedHost = "app.example.com", Port = 443, CertificateThumbprint = "A1" }
                    }
                }
            };

            var diff = CertificateInventoryDiffAnalyzer.BuildDiff(snapshots, includeUnchanged: false);
            Assert.Equal(now.AddHours(-2), diff.PreviousCapturedAtUtc);
            Assert.Equal(now.AddHours(-1), diff.CurrentCapturedAtUtc);
            Assert.Empty(diff.Endpoints);
            Assert.Equal(1, diff.UnchangedCount);

            var withUnchanged = CertificateInventoryDiffAnalyzer.BuildDiff(snapshots, includeUnchanged: true);
            Assert.Single(withUnchanged.Endpoints);
            Assert.Equal("Unchanged", withUnchanged.Endpoints[0].Status);
        }

        [Fact]
        public void BuildDiffReturnsNullPreviousWhenSelectorPredatesInventory() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddHours(-2),
                    Entries = new List<CertificateInventoryEntry> {
                        new() { Host = "app.example.com", ResolvedHost = "app.example.com", Port = 443, CertificateThumbprint = "A1" }
                    }
                },
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddHours(-1),
                    Entries = new List<CertificateInventoryEntry> {
                        new() { Host = "app.example.com", ResolvedHost = "app.example.com", Port = 443, CertificateThumbprint = "A2" }
                    }
                }
            };

            var diff = CertificateInventoryDiffAnalyzer.BuildDiff(
                snapshots,
                previousCapturedAtUtc: now.AddDays(-10),
                currentCapturedAtUtc: now);

            Assert.Equal(now.AddDays(-10), diff.RequestedPreviousCapturedAtUtc);
            Assert.Equal(now, diff.RequestedCurrentCapturedAtUtc);
            Assert.Null(diff.PreviousCapturedAtUtc);
            Assert.Equal(now.AddHours(-1), diff.CurrentCapturedAtUtc);
            Assert.Equal(0, diff.PreviousEndpointCount);
            Assert.Equal(1, diff.CurrentEndpointCount);
            Assert.Equal(1, diff.AddedCount);
            Assert.Equal(0, diff.RemovedCount);
            Assert.Equal(0, diff.ChangedCount);
            Assert.Contains(diff.Warnings, warning =>
                warning.Contains("Requested previous snapshot", StringComparison.OrdinalIgnoreCase));
        }

        [Fact]
        public void BuildDiffAddsWarningWhenRequestedCurrentSnapshotIsUnavailable() {
            var now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddHours(-2),
                    Entries = new List<CertificateInventoryEntry> {
                        new() { Host = "app.example.com", ResolvedHost = "app.example.com", Port = 443, CertificateThumbprint = "A1" }
                    }
                },
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now.AddHours(-1),
                    Entries = new List<CertificateInventoryEntry> {
                        new() { Host = "app.example.com", ResolvedHost = "app.example.com", Port = 443, CertificateThumbprint = "A2" }
                    }
                }
            };

            var diff = CertificateInventoryDiffAnalyzer.BuildDiff(
                snapshots,
                currentCapturedAtUtc: now.AddDays(-5));

            Assert.Equal(now.AddDays(-5), diff.RequestedCurrentCapturedAtUtc);
            Assert.Equal(now.AddHours(-1), diff.CurrentCapturedAtUtc);
            Assert.Contains(diff.Warnings, warning =>
                warning.Contains("Requested current snapshot", StringComparison.OrdinalIgnoreCase) &&
                warning.Contains("using latest snapshot", StringComparison.OrdinalIgnoreCase));
        }
    }
}

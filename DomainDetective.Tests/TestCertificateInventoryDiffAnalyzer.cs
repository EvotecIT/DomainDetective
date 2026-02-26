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

            Assert.Equal(previous.CapturedAtUtc, diff.PreviousCapturedAtUtc);
            Assert.Equal(current.CapturedAtUtc, diff.CurrentCapturedAtUtc);
            Assert.Equal(3, diff.PreviousEndpointCount);
            Assert.Equal(3, diff.CurrentEndpointCount);
            Assert.Equal(1, diff.AddedCount);
            Assert.Equal(1, diff.RemovedCount);
            Assert.Equal(1, diff.ChangedCount);
            Assert.Equal(1, diff.UnchangedCount);

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
    }
}

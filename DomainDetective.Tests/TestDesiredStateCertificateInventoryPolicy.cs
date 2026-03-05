using System;
using System.Collections.Generic;
using System.IO;
using DomainDetective.Definitions;
using DomainDetective.DesiredState;
using Xunit;

namespace DomainDetective.Tests;

public sealed class TestDesiredStateCertificateInventoryPolicy {
    [Fact]
    public void Resolve_UsesDesiredStateCertificateInventoryProfile() {
        var config = new DesiredStateConfiguration {
            Defaults = new DesiredStateProfile {
                CertificateInventory = new DesiredStateCertificateInventoryPolicy {
                    Enabled = true,
                    BaselineProfile = "Balanced",
                    IncludeCompliant = false,
                    MaxEndpoints = 300
                }
            },
            Overrides = new List<DesiredStateOverride> {
                new DesiredStateOverride {
                    Match = new DesiredStateMatch {
                        DomainPatterns = new[] { "*.example.com" },
                        Classifications = new[] { MailDomainClassificationCategory.Parked }
                    },
                    Profile = new DesiredStateProfile {
                        CertificateInventory = new DesiredStateCertificateInventoryPolicy {
                            BaselineProfile = "Strict",
                            IncludeCompliant = true,
                            MaxEndpoints = 50
                        }
                    }
                }
            }
        };

        var resolved = DesiredStateCertificateInventoryPolicyResolver.Resolve(
            "parked.example.com",
            config,
            MailDomainClassificationCategory.Parked);

        Assert.True(resolved.Enabled);
        Assert.Equal("Strict", resolved.BaselineProfile);
        Assert.True(resolved.IncludeCompliant);
        Assert.Equal(50, resolved.MaxEndpoints);
    }

    [Fact]
    public void Resolve_LoadsRelativePolicyOverridesPath_AndEvaluateUsesIt() {
        string tempDirectory = Path.Combine(Path.GetTempPath(), "dd-cert-ds-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDirectory);
        try {
            string overridesPath = Path.Combine(tempDirectory, "policy-overrides.json");
            File.WriteAllText(
                overridesPath,
                "{\n  \"version\": 1,\n  \"defaults\": {\n    \"maxPrivateAuthorityReuseEndpointCount\": 2\n  },\n  \"rules\": []\n}");

            var config = new DesiredStateConfiguration {
                Defaults = new DesiredStateProfile {
                    CertificateInventory = new DesiredStateCertificateInventoryPolicy {
                        Enabled = true,
                        BaselineProfile = "Balanced",
                        PolicyOverridesPath = "policy-overrides.json"
                    }
                }
            };

            var resolved = DesiredStateCertificateInventoryPolicyResolver.Resolve(
                "corp.example.com",
                config,
                configurationPath: Path.Combine(tempDirectory, "desired-state.json"));

            Assert.True(resolved.Enabled);
            Assert.Equal(Path.GetFullPath(overridesPath), resolved.ResolvedPolicyOverridesPath);
            Assert.NotNull(resolved.PolicyOverrides);

            DateTimeOffset now = DateTimeOffset.UtcNow;
            var snapshots = new[] {
                new CertificateInventorySnapshot {
                    CapturedAtUtc = now,
                    Port = 443,
                    Entries = new List<CertificateInventoryEntry> {
                        BuildPrivateReusableEntry(now, "private-1.corp.example.com", "AA11"),
                        BuildPrivateReusableEntry(now, "private-2.corp.example.com", "AA11"),
                        BuildPrivateReusableEntry(now, "private-3.corp.example.com", "AA11")
                    }
                }
            };

            var policy = DesiredStateCertificateInventoryPolicyResolver.Evaluate(snapshots, resolved);

            Assert.Equal("Balanced", policy.BaselineProfile);
            Assert.Equal(3, policy.EndpointCount);
            Assert.Equal(3, policy.ViolationEndpointCount);
            Assert.All(policy.Endpoints, endpoint =>
                Assert.Contains(endpoint.Violations, violation => violation.Code == CertificateInventoryPolicyViolationCodes.ReuseEndpointFanout));
        } finally {
            try {
                Directory.Delete(tempDirectory, true);
            } catch {
                // no-op
            }
        }
    }

    private static CertificateInventoryEntry BuildPrivateReusableEntry(DateTimeOffset now, string host, string thumbprint) {
        return new CertificateInventoryEntry {
            Host = host,
            ResolvedHost = host,
            Port = 443,
            Service = "HTTPS",
            NotBeforeUtc = now.AddDays(-30),
            NotAfterUtc = now.AddDays(120),
            Valid = true,
            Expired = false,
            ChainComplete = true,
            IsReachable = true,
            HostnameMatch = true,
            IsSelfSigned = false,
            IsKnownCertificateAuthority = false,
            IsKnownRootCertificateAuthority = false,
            PresentInCtLogs = false,
            AllowsServerAuthentication = true,
            AllowsClientAuthentication = false,
            AllowsSecureEmail = false,
            CertificateIssuerNormalized = "Internal Issuer",
            CertificateRootIssuerNormalized = "Internal Root",
            CertificateThumbprint = thumbprint
        };
    }
}

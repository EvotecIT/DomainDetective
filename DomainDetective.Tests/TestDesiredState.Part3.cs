using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using DnsClientX;
using DomainDetective.Definitions;
using DomainDetective.DesiredState;

namespace DomainDetective.Tests;

public sealed partial class TestDesiredState {
    [Fact]
    public async Task Evaluate_SoaSerialFormatRequired_AddsWarning() {
        var health = new DomainHealthCheck();
        await health.CheckSOA("ns1.example.com. hostmaster.example.com. 1 3600 600 1209600 3600");

        var profile = new DesiredStateProfile {
            Soa = new DesiredStateSoaPolicy {
                RequireSerialFormat = true
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Warning &&
            string.Equals(a.Code, DesiredStateCodes.SoaSerialFormatInvalid, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Evaluate_SoaRefreshOutOfRange_AddsWarning() {
        var health = new DomainHealthCheck();
        await health.CheckSOA("ns1.example.com. hostmaster.example.com. 2025010101 300 600 1209600 3600");

        var profile = new DesiredStateProfile {
            Soa = new DesiredStateSoaPolicy {
                MinRefresh = 1800,
                MaxRefresh = 86400
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Warning &&
            string.Equals(a.Code, DesiredStateCodes.SoaRefreshOutOfRange, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Evaluate_DaneInvalidRecords_AddsError() {
        var health = new DomainHealthCheck();
        await health.CheckDANE("4 1 1 abc");

        var profile = new DesiredStateProfile {
            Dane = new DesiredStateDanePolicy {
                RequireValidRecords = true
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Error &&
            string.Equals(a.Code, DesiredStateCodes.DaneInvalidRecords, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Evaluate_DelegationMismatch_AddsError() {
        var health = new DomainHealthCheck();
        typeof(NSAnalysis).GetProperty("DelegationMatches", BindingFlags.Instance | BindingFlags.Public)!.SetValue(health.NSAnalysis, false);

        var profile = new DesiredStateProfile {
            Delegation = new DesiredStateDelegationPolicy {
                RequireMatchesParent = true
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Error &&
            string.Equals(a.Code, DesiredStateCodes.DelegationMismatch, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Evaluate_ZoneTransferAllowed_AddsError() {
        var health = new DomainHealthCheck();
        health.ZoneTransferAnalysis.ServerResults["ns1.example.com"] = true;

        var profile = new DesiredStateProfile {
            ZoneTransfer = new DesiredStateZoneTransferPolicy {
                DisallowUnauthenticatedAxfr = true
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Error &&
            string.Equals(a.Code, DesiredStateCodes.ZoneTransferAllowed, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Evaluate_WildcardDnsCatchAllNotAllowed_AddsWarning() {
        var health = new DomainHealthCheck();
        typeof(WildcardDnsAnalysis).GetProperty("CatchAll", BindingFlags.Instance | BindingFlags.Public)!.SetValue(health.WildcardDnsAnalysis, true);

        var profile = new DesiredStateProfile {
            WildcardDns = new DesiredStateWildcardDnsPolicy {
                ExpectedCatchAll = false
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Warning &&
            string.Equals(a.Code, DesiredStateCodes.WildcardCatchAllNotAllowed, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void AssessmentPolicy_SuppressesAndOverridesSeverity() {
        var health = new DomainHealthCheck();
        health.DmarcAnalysis.Assessments.Add(new Assessment {
            Severity = AssessmentSeverity.Warning,
            Category = "DMARC",
            Code = "DMARC.Alignment.Mismatch",
            Message = "alignment mismatch"
        });
        health.DmarcAnalysis.Assessments.Add(new Assessment {
            Severity = AssessmentSeverity.Warning,
            Category = "DMARC",
            Code = "DMARC.Tag.Deprecated",
            Message = "deprecated tag"
        });

        var policy = new DesiredStateAssessmentPolicy {
            SuppressCodes = new[] { "DMARC.Alignment.Mismatch" },
            SeverityOverrides = new Dictionary<string, AssessmentSeverity>(StringComparer.OrdinalIgnoreCase) {
                ["DMARC.Tag.Deprecated"] = AssessmentSeverity.Info
            }
        };

        DesiredStateEvaluator.ApplyAssessmentPolicy(health, policy);

        Assert.DoesNotContain(health.DmarcAnalysis.Assessments, a => string.Equals(a.Code, "DMARC.Alignment.Mismatch", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(health.DmarcAnalysis.Assessments, a => string.Equals(a.Code, "DMARC.Tag.Deprecated", StringComparison.OrdinalIgnoreCase) && a.Severity == AssessmentSeverity.Info);
    }

    [Fact]
    public void Evaluate_IncludesHealthAssessments_AndAppliesPolicy() {
        var health = new DomainHealthCheck();
        health.DmarcAnalysis.Assessments.Add(new Assessment {
            Severity = AssessmentSeverity.Warning,
            Category = "DMARC",
            Code = "DMARC.Alignment.Mismatch",
            Message = "alignment mismatch"
        });
        health.DmarcAnalysis.Assessments.Add(new Assessment {
            Severity = AssessmentSeverity.Warning,
            Category = "DMARC",
            Code = "DMARC.Tag.Deprecated",
            Message = "deprecated tag"
        });

        var profile = new DesiredStateProfile {
            AssessmentPolicy = new DesiredStateAssessmentPolicy {
                SuppressCodes = new[] { "DMARC.Alignment.Mismatch" },
                SeverityOverrides = new Dictionary<string, AssessmentSeverity>(StringComparer.OrdinalIgnoreCase) {
                    ["DMARC.Tag.Deprecated"] = AssessmentSeverity.Info
                }
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.True(result.Conforms);
        Assert.DoesNotContain(result.Assessments, a => string.Equals(a.Code, "DMARC.Alignment.Mismatch", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(result.Assessments, a => string.Equals(a.Code, "DMARC.Tag.Deprecated", StringComparison.OrdinalIgnoreCase) && a.Severity == AssessmentSeverity.Info);
    }

    [Fact]
    public async Task Evaluate_ApexAddressPrivateNotAllowed_AddsError() {
        var health = new DomainHealthCheck();

        await health.ApexAddressAnalysis.AnalyzeApexAnswers(
            new[] { new DnsAnswer { DataRaw = "10.0.0.1", Type = DnsRecordType.A } },
            Array.Empty<DnsAnswer>());

        var profile = new DesiredStateProfile {
            ApexAddress = new DesiredStateApexAddressPolicy {
                DisallowPrivateAddresses = true
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Error &&
            string.Equals(a.Code, DesiredStateCodes.ApexAddressPrivateNotAllowed, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Evaluate_RpkiInvalid_AddsError() {
        var health = new DomainHealthCheck();
        health.RpkiAnalysis.QueryDnsOverride = (_, type) => {
            if (type == DnsRecordType.A) {
                return Task.FromResult(new[] {
                    new DnsAnswer { DataRaw = "192.0.2.1", Type = DnsRecordType.A }
                });
            }
            return Task.FromResult(Array.Empty<DnsAnswer>());
        };
        health.RpkiAnalysis.QueryRpkiOverride = _ => Task.FromResult(("192.0.2.0/24", 64500, false));

        await health.VerifyRPKI("example.com");

        var profile = new DesiredStateProfile {
            Rpki = new DesiredStateRpkiPolicy {
                DisallowInvalid = true
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Error &&
            string.Equals(a.Code, DesiredStateCodes.RpkiInvalid, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Evaluate_EdnsNotSupported_AddsError() {
        var health = new DomainHealthCheck();
        health.EdnsSupportAnalysis.ServerSupport["ns1.provider.example (192.0.2.1)"] = new EdnsSupportInfo {
            Supported = false,
            UdpPayloadSize = 0,
            DoBit = false,
            TruncatedUdp = false,
            Version = 0,
            CookieSupported = false,
            CookieLength = 0
        };

        var profile = new DesiredStateProfile {
            EdnsSupport = new DesiredStateEdnsSupportPolicy {
                RequireAllServersSupported = true
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Error &&
            string.Equals(a.Code, DesiredStateCodes.EdnsNotSupported, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Evaluate_DnsOverTlsAnySupportedRequired_AddsError() {
        var health = new DomainHealthCheck();
        health.DnsOverTlsAnalysis.ServerResults["ns1.provider.example (192.0.2.1)"] = new DnsOverTlsEndpointResult {
            NameServerHost = "ns1.provider.example",
            ServerIp = "192.0.2.1",
            Port = 853,
            Supported = false,
            Error = "refused"
        };

        var profile = new DesiredStateProfile {
            DnsOverTls = new DesiredStateDnsOverTlsPolicy {
                RequireAnySupported = true
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Error &&
            string.Equals(a.Code, DesiredStateCodes.DnsOverTlsAnySupportedRequired, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Evaluate_FlatteningServiceTargetSuffixMismatch_AddsError() {
        var health = new DomainHealthCheck();
        typeof(FlatteningServiceAnalysis).GetProperty("CnameRecordExists", BindingFlags.Instance | BindingFlags.Public)!.SetValue(health.FlatteningServiceAnalysis, true);
        typeof(FlatteningServiceAnalysis).GetProperty("Target", BindingFlags.Instance | BindingFlags.Public)!.SetValue(health.FlatteningServiceAnalysis, "edge.bad.example");

        var profile = new DesiredStateProfile {
            FlatteningService = new DesiredStateFlatteningServicePolicy {
                AllowedTargetSuffixes = new[] { "cloudflare.net" }
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Error &&
            string.Equals(a.Code, DesiredStateCodes.FlatteningServiceTargetNotAllowed, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Evaluate_AutodiscoverCnameTargetSuffixMismatch_AddsError() {
        var health = new DomainHealthCheck();
        SetBackingField(health.AutodiscoverAnalysis, "AutodiscoverCnameExists", true);
        SetBackingField(health.AutodiscoverAnalysis, "AutodiscoverTarget", "autodiscover.bad.example");

        var profile = new DesiredStateProfile {
            Autodiscover = new DesiredStateAutodiscoverPolicy {
                AllowedAutodiscoverCnameTargetSuffixes = new[] { "outlook.com" }
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Error &&
            string.Equals(a.Code, DesiredStateCodes.AutodiscoverCnameTargetNotAllowed, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Evaluate_SecurityTxtContactEmailDomainSuffixMismatch_AddsError() {
        var health = new DomainHealthCheck();
        health.SecurityTXTAnalysis.RecordPresent = true;
        health.SecurityTXTAnalysis.ContactEmail.Add("security@bad.example");

        var profile = new DesiredStateProfile {
            SecurityTxt = new DesiredStateSecurityTxtPolicy {
                AllowedContactEmailDomainSuffixes = new[] { "example.com" }
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Error &&
            string.Equals(a.Code, DesiredStateCodes.SecurityTxtContactEmailDomainNotAllowed, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Evaluate_RobotsSitemapRequired_AddsWarning() {
        var health = new DomainHealthCheck();
        SetBackingField(health.RobotsTxtAnalysis, "RecordPresent", true);
        SetBackingField(health.RobotsTxtAnalysis, "Robots", new RobotsFile());

        var profile = new DesiredStateProfile {
            Robots = new DesiredStateRobotsPolicy {
                RequireSitemap = true
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Warning &&
            string.Equals(a.Code, DesiredStateCodes.RobotsSitemapRequired, StringComparison.OrdinalIgnoreCase));
    }

    private static void SetBackingField(object instance, string propertyName, object? value) {
        var field = instance.GetType().GetField($"<{propertyName}>k__BackingField", BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.NotNull(field);
        field!.SetValue(instance, value);
    }
}

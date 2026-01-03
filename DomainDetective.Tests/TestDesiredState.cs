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

public sealed class TestDesiredState {
    [Fact]
    public void ResolveProfile_AppliesClassificationOverrideWithoutClobberingDefaults() {
        var json = @"
{
  ""version"": 1,
  ""defaults"": {
    ""checks"": [ ""DMARC"", ""SPF"" ],
    ""dmarc"": {
      ""allowedPolicies"": [ ""reject"" ],
      ""requireRua"": true,
      ""allowedReportDomainSuffixes"": [ ""dmarc.powermarc.com"" ]
    },
    ""spf"": {
      ""allowedAllMechanisms"": [ ""-all"", ""~all"" ],
      ""maxDnsLookups"": 10
    }
  },
  ""overrides"": [
    {
      ""match"": {
        ""domainPatterns"": [ ""*.example.com"" ],
        ""classifications"": [ ""Parked"" ]
      },
      ""profile"": {
        ""spf"": { ""requireDenyAll"": true }
      }
    }
  ]
}";

        var file = Path.GetTempFileName();
        try {
            File.WriteAllText(file, json);
            var cfg = DesiredStateConfiguration.Load(file);

            Assert.True(cfg.RequiresMailClassification());

            var profile = cfg.ResolveProfile("a.example.com", MailDomainClassificationCategory.Parked);

            Assert.NotNull(profile.Dmarc);
            Assert.NotNull(profile.Spf);
            Assert.True(profile.Spf!.RequireDenyAll == true);
            Assert.Equal(10, profile.Spf.MaxDnsLookups);
            Assert.Contains("dmarc.powermarc.com", profile.Dmarc!.AllowedReportDomainSuffixes ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
        } finally {
            File.Delete(file);
        }
    }

    [Fact]
    public async Task Evaluate_DmarcRuaDomainSuffixMismatch_AddsError() {
        var health = new DomainHealthCheck();

        var record = "v=DMARC1; p=reject; rua=mailto:agg@reports.vendor.example";
        await health.CheckDMARC(record);

        var profile = new DesiredStateProfile {
            Dmarc = new DesiredStateDmarcPolicy {
                AllowedReportDomainSuffixes = new[] { "dmarc.powermarc.com" },
                RequireRecord = true
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Error &&
            string.Equals(a.Code, DesiredStateCodes.DmarcRuaDomainNotAllowed, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Evaluate_DmarcAspfNotAllowed_AddsError() {
        var health = new DomainHealthCheck();

        var record = "v=DMARC1; p=reject; aspf=r; rua=mailto:agg@dmarc.powermarc.com";
        await health.CheckDMARC(record);

        var profile = new DesiredStateProfile {
            Dmarc = new DesiredStateDmarcPolicy {
                AllowedAspfAlignments = new[] { "s" },
                RequireRecord = true
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Error &&
            string.Equals(a.Code, DesiredStateCodes.DmarcAspfNotAllowed, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Evaluate_DkimRequiredSelectorMissing_AddsError() {
        var health = new DomainHealthCheck();
        health.DKIMAnalysis.AnalysisResults["selector1"] = new DkimRecordAnalysis {
            DkimRecordExists = true,
            KeyLength = 2048,
            CnameTarget = "s1.sendgrid.net"
        };

        var profile = new DesiredStateProfile {
            Dkim = new DesiredStateDkimPolicy {
                RequiredSelectors = new[] { "selector1", "selector2" }
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingOnly);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Error &&
            string.Equals(a.Code, DesiredStateCodes.DkimSelectorMissing, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Evaluate_TlsRptMissingRecord_AddsWarning() {
        var health = new DomainHealthCheck();

        var profile = new DesiredStateProfile {
            TlsRpt = new DesiredStateTlsRptPolicy {
                RequireRecord = true
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Warning &&
            string.Equals(a.Code, DesiredStateCodes.TlsRptMissingRecord, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Evaluate_TlsRptRuaDomainSuffixMismatch_AddsError() {
        var health = new DomainHealthCheck();

        var record = "v=TLSRPTv1; rua=mailto:agg@reports.vendor.example";
        await health.CheckTLSRPT(record);

        var profile = new DesiredStateProfile {
            TlsRpt = new DesiredStateTlsRptPolicy {
                RequireRecord = true,
                AllowedReportDomainSuffixes = new[] { "tlsrpt.vendor.example" }
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Error &&
            string.Equals(a.Code, DesiredStateCodes.TlsRptRuaDomainNotAllowed, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Evaluate_SpfRequiredIncludeMissing_AddsError() {
        var health = new DomainHealthCheck();

        await health.CheckSPF("v=spf1 -all");

        var profile = new DesiredStateProfile {
            Spf = new DesiredStateSpfPolicy {
                RequireRecord = true,
                RequiredIncludeDomains = new[] { "spf.protection.outlook.com" }
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingOnly);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Error &&
            string.Equals(a.Code, DesiredStateCodes.SpfRequiredIncludeMissing, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Evaluate_BimiMissingRecord_AddsWarning() {
        var health = new DomainHealthCheck();

        var profile = new DesiredStateProfile {
            Bimi = new DesiredStateBimiPolicy {
                RequireRecord = true
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Warning &&
            string.Equals(a.Code, DesiredStateCodes.BimiMissingRecord, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Evaluate_BimiLocationHostSuffixMismatch_AddsError() {
        var health = new DomainHealthCheck();

        var record = "v=BIMI1; l=https://logo.bad.example/logo.svg; a=";
        await health.CheckBIMI(record, skipIndicatorDownload: true);

        var profile = new DesiredStateProfile {
            Bimi = new DesiredStateBimiPolicy {
                RequireValidLocation = true,
                AllowedLocationHostSuffixes = new[] { "cdn.vendor.example" },
                SkipIndicatorDownload = true
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Error &&
            string.Equals(a.Code, DesiredStateCodes.BimiLocationHostNotAllowed, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Evaluate_MxNullMxNotAllowed_AddsError() {
        var health = new DomainHealthCheck();

        await health.CheckMX("0 .");

        var profile = new DesiredStateProfile {
            Mx = new DesiredStateMxPolicy {
                DisallowNullMx = true
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Error &&
            string.Equals(a.Code, DesiredStateCodes.MxNullMxNotAllowed, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Evaluate_NsTooFewRecords_AddsWarning() {
        var health = new DomainHealthCheck();
        health.NSAnalysis.EnableChaosFingerprinting = false;
        health.NSAnalysis.LookupAsnOverride = _ => Task.FromResult<int?>(64500);
        health.NSAnalysis.QueryDnsOverride = (name, type) => {
            var normalized = name.Trim().TrimEnd('.');
            if (type == DnsRecordType.A && string.Equals(normalized, "ns1.provider.example", StringComparison.OrdinalIgnoreCase)) {
                return Task.FromResult(new[] {
                    new DnsAnswer { DataRaw = "192.0.2.1", Type = DnsRecordType.A }
                });
            }

            return Task.FromResult(Array.Empty<DnsAnswer>());
        };

        await health.CheckNS("ns1.provider.example.");

        var profile = new DesiredStateProfile {
            Ns = new DesiredStateNsPolicy {
                RequireAtLeastTwo = true
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Warning &&
            string.Equals(a.Code, DesiredStateCodes.NsTooFewRecords, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Evaluate_CaaIssuerNotAllowed_AddsError() {
        var health = new DomainHealthCheck();

        await health.CheckCAA("0 issue \"letsencrypt.org\"");

        var profile = new DesiredStateProfile {
            Caa = new DesiredStateCaaPolicy {
                RequireRecord = true,
                AllowedCertificateIssuers = new[] { "digicert.com" }
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Error &&
            string.Equals(a.Code, DesiredStateCodes.CaaIssuerNotAllowed, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Evaluate_DnssecChainInvalid_AddsError() {
        var health = new DomainHealthCheck();
        var chainProp = typeof(DnsSecAnalysis).GetProperty("ChainValid", BindingFlags.Instance | BindingFlags.Public)!;
        chainProp.SetValue(health.DnsSecAnalysis, false);

        var profile = new DesiredStateProfile {
            DnsSec = new DesiredStateDnssecPolicy {
                RequireChainValid = true
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Error &&
            string.Equals(a.Code, DesiredStateCodes.DnssecChainInvalid, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Evaluate_DnssecRrsigDaysRemainingTooLow_AddsWarning() {
        var health = new DomainHealthCheck();
        var chainProp = typeof(DnsSecAnalysis).GetProperty("ChainValid", BindingFlags.Instance | BindingFlags.Public)!;
        chainProp.SetValue(health.DnsSecAnalysis, true);

        var rrsigsProp = typeof(DnsSecAnalysis).GetProperty("Rrsigs", BindingFlags.Instance | BindingFlags.Public)!;
        rrsigsProp.SetValue(health.DnsSecAnalysis, new List<RrsigInfo> {
            new RrsigInfo {
                Inception = DateTimeOffset.UtcNow.AddDays(-1),
                Expiration = DateTimeOffset.UtcNow.AddDays(1)
            }
        });

        var profile = new DesiredStateProfile {
            DnsSec = new DesiredStateDnssecPolicy {
                MinRrsigDaysRemaining = 7
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Warning &&
            string.Equals(a.Code, DesiredStateCodes.DnssecRrsigExpiringSoon, StringComparison.OrdinalIgnoreCase));
    }

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
}

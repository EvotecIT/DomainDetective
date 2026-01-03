using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
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

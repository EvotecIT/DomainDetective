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

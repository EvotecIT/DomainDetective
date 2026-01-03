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
    public async Task Evaluate_DmarcInvalidRecordWhenRequired_AddsError() {
        var health = new DomainHealthCheck();

        var record = "v=DMARC1; rua=mailto:agg@dmarc.powermarc.com";
        await health.CheckDMARC(record);

        var profile = new DesiredStateProfile {
            Dmarc = new DesiredStateDmarcPolicy {
                RequireRecord = true,
                RequireValidRecord = true,
                RequireExternalReportAuthorization = false
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Error &&
            string.Equals(a.Code, DesiredStateCodes.DmarcInvalidRecord, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Evaluate_DmarcMultipleRecordsNotAllowed_AddsError() {
        var health = new DomainHealthCheck();

        var record = "v=DMARC1; p=reject; rua=mailto:agg@dmarc.powermarc.com";
        await health.CheckDMARC(record);

        typeof(DmarcAnalysis).GetProperty("MultipleRecords", BindingFlags.Instance | BindingFlags.Public)!.SetValue(health.DmarcAnalysis, true);

        var profile = new DesiredStateProfile {
            Dmarc = new DesiredStateDmarcPolicy {
                RequireSingleRecord = true,
                RequireExternalReportAuthorization = false
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Error &&
            string.Equals(a.Code, DesiredStateCodes.DmarcMultipleRecordsNotAllowed, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Evaluate_DmarcRufNotAllowed_AddsError() {
        var health = new DomainHealthCheck();

        var record = "v=DMARC1; p=reject; rua=mailto:agg@dmarc.powermarc.com; ruf=mailto:forensic@dmarc.powermarc.com";
        await health.CheckDMARC(record);

        var profile = new DesiredStateProfile {
            Dmarc = new DesiredStateDmarcPolicy {
                DisallowRuf = true,
                RequireExternalReportAuthorization = false
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Error &&
            string.Equals(a.Code, DesiredStateCodes.DmarcRufNotAllowed, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Evaluate_DmarcHttpRufNotAllowed_AddsError() {
        var health = new DomainHealthCheck();

        var record = "v=DMARC1; p=reject; rua=mailto:agg@dmarc.powermarc.com; ruf=https://forensics.example/report";
        await health.CheckDMARC(record);

        var profile = new DesiredStateProfile {
            Dmarc = new DesiredStateDmarcPolicy {
                DisallowHttpRuf = true,
                RequireExternalReportAuthorization = false
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Error &&
            string.Equals(a.Code, DesiredStateCodes.DmarcHttpRufNotAllowed, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Evaluate_DmarcWeakPolicyNotAllowed_AddsError() {
        var health = new DomainHealthCheck();

        var record = "v=DMARC1; p=none; rua=mailto:agg@dmarc.powermarc.com";
        await health.CheckDMARC(record);

        var profile = new DesiredStateProfile {
            Dmarc = new DesiredStateDmarcPolicy {
                DisallowWeakPolicy = true,
                RequireExternalReportAuthorization = false
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Error &&
            string.Equals(a.Code, DesiredStateCodes.DmarcWeakPolicyNotAllowed, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Evaluate_DmarcMailtoRuaMissing_AddsError() {
        var health = new DomainHealthCheck();

        var record = "v=DMARC1; p=reject; rua=https://reports.example/report";
        await health.CheckDMARC(record);

        var profile = new DesiredStateProfile {
            Dmarc = new DesiredStateDmarcPolicy {
                RequireMailtoRua = true,
                RequireExternalReportAuthorization = false
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Error &&
            string.Equals(a.Code, DesiredStateCodes.DmarcMailtoRuaMissing, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Evaluate_DmarcHttpRuaNotAllowed_AddsError() {
        var health = new DomainHealthCheck();

        var record = "v=DMARC1; p=reject; rua=https://reports.example/report";
        await health.CheckDMARC(record);

        var profile = new DesiredStateProfile {
            Dmarc = new DesiredStateDmarcPolicy {
                DisallowHttpRua = true,
                RequireExternalReportAuthorization = false
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Error &&
            string.Equals(a.Code, DesiredStateCodes.DmarcHttpRuaNotAllowed, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Evaluate_DmarcDeprecatedTagsNotAllowed_AddsWarning() {
        var health = new DomainHealthCheck();

        var record = "v=DMARC1; p=reject; rua=mailto:agg@dmarc.powermarc.com; pct=100";
        await health.CheckDMARC(record);

        var profile = new DesiredStateProfile {
            Dmarc = new DesiredStateDmarcPolicy {
                DisallowDeprecatedTags = true,
                RequireExternalReportAuthorization = false
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Warning &&
            string.Equals(a.Code, DesiredStateCodes.DmarcDeprecatedTagsNotAllowed, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Evaluate_DmarcUnknownTagsNotAllowed_AddsWarning() {
        var health = new DomainHealthCheck();

        var record = "v=DMARC1; p=reject; rua=mailto:agg@dmarc.powermarc.com; foo=bar";
        await health.CheckDMARC(record);

        var profile = new DesiredStateProfile {
            Dmarc = new DesiredStateDmarcPolicy {
                DisallowUnknownTags = true,
                RequireExternalReportAuthorization = false
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Warning &&
            string.Equals(a.Code, DesiredStateCodes.DmarcUnknownTagsNotAllowed, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Evaluate_DmarcRecordOver255NotAllowed_AddsWarning() {
        var health = new DomainHealthCheck();

        var record = "v=DMARC1; p=reject; rua=mailto:agg@dmarc.powermarc.com";
        await health.CheckDMARC(record);

        typeof(DmarcAnalysis).GetProperty("ExceedsCharacterLimit", BindingFlags.Instance | BindingFlags.Public)!.SetValue(health.DmarcAnalysis, true);

        var profile = new DesiredStateProfile {
            Dmarc = new DesiredStateDmarcPolicy {
                DisallowRecordOver255 = true,
                RequireExternalReportAuthorization = false
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Warning &&
            string.Equals(a.Code, DesiredStateCodes.DmarcRecordTooLong, StringComparison.OrdinalIgnoreCase));
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
    public void Evaluate_DkimWeakKeyNotAllowed_AddsError() {
        var health = new DomainHealthCheck();
        health.DKIMAnalysis.AnalysisResults["selector1"] = new DkimRecordAnalysis {
            DkimRecordExists = true,
            StartsCorrectly = true,
            PublicKeyExists = true,
            ValidPublicKey = true,
            ValidKeyType = true,
            KeyLength = 1024,
            WeakKey = true
        };

        var profile = new DesiredStateProfile {
            Dkim = new DesiredStateDkimPolicy {
                DisallowWeakKeys = true
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingOnly);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Error &&
            string.Equals(a.Code, DesiredStateCodes.DkimWeakKeyNotAllowed, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Evaluate_DkimDeprecatedTagsNotAllowed_AddsWarning() {
        var health = new DomainHealthCheck();
        var analysis = new DkimRecordAnalysis {
            DkimRecordExists = true,
            StartsCorrectly = true,
            PublicKeyExists = true,
            ValidPublicKey = true,
            ValidKeyType = true,
            KeyLength = 2048,
            ValidRsaKeyLength = true
        };
        analysis.DeprecatedTags.Add("q");
        health.DKIMAnalysis.AnalysisResults["selector1"] = analysis;

        var profile = new DesiredStateProfile {
            Dkim = new DesiredStateDkimPolicy {
                DisallowDeprecatedTags = true
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingOnly);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Warning &&
            string.Equals(a.Code, DesiredStateCodes.DkimDeprecatedTagsNotAllowed, StringComparison.OrdinalIgnoreCase));
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
    public async Task Evaluate_TlsRptHttpsRuaNotAllowed_AddsError() {
        var health = new DomainHealthCheck();

        var record = "v=TLSRPTv1; rua=https://reports.vendor.example/tlsrpt";
        await health.CheckTLSRPT(record);

        var profile = new DesiredStateProfile {
            TlsRpt = new DesiredStateTlsRptPolicy {
                DisallowHttpRua = true
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Error &&
            string.Equals(a.Code, DesiredStateCodes.TlsRptHttpRuaNotAllowed, StringComparison.OrdinalIgnoreCase));
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
    public void Evaluate_MtastsDnsRecordInvalid_AddsError() {
        var health = new DomainHealthCheck();

        typeof(MTASTSAnalysis).GetProperty("DnsRecordPresent", BindingFlags.Instance | BindingFlags.Public)!.SetValue(health.MTASTSAnalysis, true);
        typeof(MTASTSAnalysis).GetProperty("DnsRecordValid", BindingFlags.Instance | BindingFlags.Public)!.SetValue(health.MTASTSAnalysis, false);

        var profile = new DesiredStateProfile {
            Mtasts = new DesiredStateMtastsPolicy {
                RequireRecord = true,
                RequireDnsRecordValid = true
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Error &&
            string.Equals(a.Code, DesiredStateCodes.MtastsDnsRecordInvalid, StringComparison.OrdinalIgnoreCase));
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
    public async Task Evaluate_SpfAllMechanismMissing_AddsError() {
        var health = new DomainHealthCheck();

        await health.CheckSPF("v=spf1 include:spf.protection.outlook.com");

        var profile = new DesiredStateProfile {
            Spf = new DesiredStateSpfPolicy {
                RequireAllMechanism = true
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingOnly);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Error &&
            string.Equals(a.Code, DesiredStateCodes.SpfAllMechanismMissing, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Evaluate_SpfExpNotAllowed_AddsWarning() {
        var health = new DomainHealthCheck();

        await health.CheckSPF("v=spf1 exp=explain.example.com -all");

        var profile = new DesiredStateProfile {
            Spf = new DesiredStateSpfPolicy {
                DisallowExp = true
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingOnly);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Warning &&
            string.Equals(a.Code, DesiredStateCodes.SpfExpNotAllowed, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Evaluate_SpfPermErrorNotAllowed_AddsError() {
        var health = new DomainHealthCheck();

        await health.CheckSPF("v=spf1 -all");
        typeof(SpfAnalysis).GetProperty("PermError", BindingFlags.Instance | BindingFlags.Public)!.SetValue(health.SpfAnalysis, true);

        var profile = new DesiredStateProfile {
            Spf = new DesiredStateSpfPolicy {
                DisallowPermError = true
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingOnly);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Error &&
            string.Equals(a.Code, DesiredStateCodes.SpfPermErrorNotAllowed, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Evaluate_SpfCnameNotAllowed_AddsWarning() {
        var health = new DomainHealthCheck();

        await health.CheckSPF("v=spf1 -all");
        typeof(SpfAnalysis).GetProperty("IsCnameResolved", BindingFlags.Instance | BindingFlags.Public)!.SetValue(health.SpfAnalysis, true);

        var profile = new DesiredStateProfile {
            Spf = new DesiredStateSpfPolicy {
                DisallowCname = true
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingOnly);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Warning &&
            string.Equals(a.Code, DesiredStateCodes.SpfCnameNotAllowed, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Evaluate_SpfInvalidRecordWhenStartsIncorrectly_AddsError() {
        var health = new DomainHealthCheck();

        await health.CheckSPF("spf1 -all");

        var profile = new DesiredStateProfile {
            Spf = new DesiredStateSpfPolicy {
                RequireValidRecord = true
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingOnly);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Error &&
            string.Equals(a.Code, DesiredStateCodes.SpfInvalidRecord, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Evaluate_SpfInvalidRecordWhenNullLookup_AddsError() {
        var health = new DomainHealthCheck();

        await health.CheckSPF("v=spf1 include: -all");

        var profile = new DesiredStateProfile {
            Spf = new DesiredStateSpfPolicy {
                RequireValidRecord = true
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingOnly);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Error &&
            string.Equals(a.Code, DesiredStateCodes.SpfInvalidRecord, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Evaluate_SpfMultipleRecordsNotAllowed_AddsError() {
        var health = new DomainHealthCheck();

        await health.CheckSPF("v=spf1 -all");

        typeof(SpfAnalysis).GetProperty("MultipleSpfRecords", BindingFlags.Instance | BindingFlags.Public)!.SetValue(health.SpfAnalysis, true);

        var profile = new DesiredStateProfile {
            Spf = new DesiredStateSpfPolicy {
                RequireSingleRecord = true
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingOnly);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Error &&
            string.Equals(a.Code, DesiredStateCodes.SpfMultipleRecordsNotAllowed, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Evaluate_SpfEffectiveSpfSendsRequired_AddsError() {
        var health = new DomainHealthCheck();

        await health.CheckSPF("v=spf1 -all");
        await health.SpfAnalysis.ComputeEffectiveSpfSendsAsync();

        var profile = new DesiredStateProfile {
            Spf = new DesiredStateSpfPolicy {
                RequireEffectiveSpfSends = true
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingOnly);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Error &&
            string.Equals(a.Code, DesiredStateCodes.SpfEffectiveSendingRequired, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Evaluate_TtlAOutOfRange_AddsWarning() {
        var health = new DomainHealthCheck();
        typeof(DnsTtlAnalysis).GetProperty("ATtls", BindingFlags.Instance | BindingFlags.Public)!.SetValue(health.DnsTtlAnalysis, new[] { 60 });

        var profile = new DesiredStateProfile {
            Ttl = new DesiredStateTtlPolicy {
                MinASeconds = 300
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Warning &&
            string.Equals(a.Code, DesiredStateCodes.TtlAOutOfRange, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Evaluate_TtlAUniformAcrossNsRequired_AddsWarning() {
        var health = new DomainHealthCheck();
        health.DnsTtlAnalysis.ServerTtlA["192.0.2.1"] = 300;
        health.DnsTtlAnalysis.ServerTtlA["192.0.2.2"] = 600;

        var profile = new DesiredStateProfile {
            Ttl = new DesiredStateTtlPolicy {
                RequireAUniformAcrossNs = true
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Warning &&
            string.Equals(a.Code, DesiredStateCodes.TtlAUniformityRequired, StringComparison.OrdinalIgnoreCase));
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
    public void Evaluate_ReverseDnsPtrSuffixNotAllowed_AddsWarning() {
        var health = new DomainHealthCheck();
        var rdns = new ReverseDnsAnalysis.ReverseDnsResult {
            IpAddress = "192.0.2.1",
            ExpectedHost = "mx1.protection.outlook.com",
            PtrRecord = "mail.bad.example",
            FcrDnsValid = true
        };
        rdns.PtrRecords.Add("mail.bad.example");
        health.ReverseDnsAnalysis.Results.Add(rdns);

        var profile = new DesiredStateProfile {
            ReverseDns = new DesiredStateReverseDnsPolicy {
                AllowedPtrSuffixes = new[] { "protection.outlook.com" }
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Warning &&
            string.Equals(a.Code, DesiredStateCodes.ReverseDnsPtrSuffixNotAllowed, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Evaluate_FcrDnsForwardMismatch_AddsWarning() {
        var health = new DomainHealthCheck();
        health.FcrDnsAnalysis.Results.Add(new FCrDnsAnalysis.FCrDnsResult {
            IpAddress = "192.0.2.1",
            PtrRecords = new List<string> { "mail.bad.example" },
            ForwardConfirmed = false
        });

        var profile = new DesiredStateProfile {
            FcrDns = new DesiredStateFcrDnsPolicy {
                RequireAllForwardConfirmed = true
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Warning &&
            string.Equals(a.Code, DesiredStateCodes.FcrDnsForwardMismatch, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Evaluate_DnsblListed_AddsError() {
        var health = new DomainHealthCheck();
        health.DNSBLAnalysis.AllResults.Add(new DNSBLRecord {
            IpAddress = "192.0.2.1",
            IpSource = DnsblIpSource.MxA,
            SourceHost = "mx1.example.com",
            QueryKind = DnsblQueryKind.IpAddressV4,
            BlackList = "dnsbl.bad.example",
            IsBlackListed = true,
            Answer = "127.0.0.2",
            ReplyMeaning = "listed",
            FQDN = "1.2.0.192.dnsbl.bad.example",
            Query = "192.0.2.1"
        });

        var profile = new DesiredStateProfile {
            Dnsbl = new DesiredStateDnsblPolicy {
                DisallowListings = true,
                IncludeQueryKinds = new[] { DnsblQueryKind.IpAddressV4 },
                IncludeIpSources = new[] { DnsblIpSource.MxA }
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Error &&
            string.Equals(a.Code, DesiredStateCodes.DnsblListed, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Evaluate_DanglingCnameUnclaimedService_AddsError() {
        var health = new DomainHealthCheck();
        typeof(DanglingCnameAnalysis).GetProperty("CnameRecordExists", BindingFlags.Instance | BindingFlags.Public)!.SetValue(health.DanglingCnameAnalysis, true);
        typeof(DanglingCnameAnalysis).GetProperty("TargetResolves", BindingFlags.Instance | BindingFlags.Public)!.SetValue(health.DanglingCnameAnalysis, false);
        typeof(DanglingCnameAnalysis).GetProperty("KnownService", BindingFlags.Instance | BindingFlags.Public)!.SetValue(health.DanglingCnameAnalysis, true);
        typeof(DanglingCnameAnalysis).GetProperty("Target", BindingFlags.Instance | BindingFlags.Public)!.SetValue(health.DanglingCnameAnalysis, "example.azurewebsites.net");

        var profile = new DesiredStateProfile {
            DanglingCname = new DesiredStateDanglingCnamePolicy {
                DisallowUnclaimedService = true
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Error &&
            string.Equals(a.Code, DesiredStateCodes.DanglingCnameUnclaimedService, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Evaluate_DnsHealthSoaSerialInconsistent_AddsWarning() {
        var health = new DomainHealthCheck();
        health.DnsHealthAnalysis.SoaSerialByServer["192.0.2.1"] = 1;
        typeof(DnsHealthAnalysis).GetProperty("SoaSerialConsistent", BindingFlags.Instance | BindingFlags.Public)!.SetValue(health.DnsHealthAnalysis, false);

        var profile = new DesiredStateProfile {
            DnsHealth = new DesiredStateDnsHealthPolicy {
                RequireSoaSerialConsistent = true
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Warning &&
            string.Equals(a.Code, DesiredStateCodes.DnsHealthSoaSerialInconsistent, StringComparison.OrdinalIgnoreCase));
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
    public void Evaluate_StartTlsAllServersSupportedRequired_AddsError() {
        var health = new DomainHealthCheck();
        health.StartTlsAnalysis.ServerResults["mx1.example.com:25"] = true;
        health.StartTlsAnalysis.ServerResults["mx2.example.com:25"] = false;

        var profile = new DesiredStateProfile {
            StartTls = new DesiredStateStartTlsPolicy {
                RequireAllServersSupported = true
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Error &&
            string.Equals(a.Code, DesiredStateCodes.StartTlsAllSupportedRequired, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Evaluate_SmtpTlsGradeTooLow_AddsError() {
        var health = new DomainHealthCheck();
        health.SmtpTlsAnalysis.ServerResults["mx1.example.com:25"] = new MailTlsAnalysis.TlsResult {
            GradeLevel = GradeLevel.C
        };

        var profile = new DesiredStateProfile {
            SmtpTls = new DesiredStateMailTlsPolicy {
                RequireCertificateValid = false,
                RequireChainValid = false,
                RequireHostnameMatch = false,
                DisallowExpiredCertificates = false,
                DisallowLegacyProtocols = false,
                MinimumGradeLevel = GradeLevel.B
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Error &&
            string.Equals(a.Code, DesiredStateCodes.SmtpTlsGradeTooLow, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Evaluate_SmtpAuthStartTlsRequired_AddsError() {
        var health = new DomainHealthCheck();
        health.SmtpAuthAnalysis.ServerMechanisms["mx1.example.com:25"] = new[] { "LOGIN" };
        health.SmtpAuthAnalysis.ServerCapabilities["mx1.example.com:25"] = new[] { "8BITMIME" };

        var profile = new DesiredStateProfile {
            SmtpAuth = new DesiredStateSmtpAuthPolicy {
                RequireStartTlsCapabilityWhenAuth = true
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Error &&
            string.Equals(a.Code, DesiredStateCodes.SmtpAuthStartTlsRequired, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Evaluate_OpenResolverNotAllowed_AddsError() {
        var health = new DomainHealthCheck();
        health.OpenResolverAnalysis.ServerResults["ns1.example.com:53"] = true;

        var profile = new DesiredStateProfile {
            OpenResolver = new DesiredStateOpenResolverPolicy {
                DisallowOpenResolver = true
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Error &&
            string.Equals(a.Code, DesiredStateCodes.OpenResolverNotAllowed, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Evaluate_MailLatencyConnectTooSlow_AddsWarning() {
        var health = new DomainHealthCheck();
        health.MailLatencyAnalysis.ServerResults["mx1.example.com:25"] = new MailLatencyAnalysis.LatencyResult {
            ConnectSuccess = true,
            BannerSuccess = true,
            ConnectTime = TimeSpan.FromMilliseconds(2500),
            BannerTime = TimeSpan.FromMilliseconds(100)
        };

        var profile = new DesiredStateProfile {
            MailLatency = new DesiredStateMailLatencyPolicy {
                MaxConnectTimeMs = 2000
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Warning &&
            string.Equals(a.Code, DesiredStateCodes.MailLatencyConnectTooSlow, StringComparison.OrdinalIgnoreCase));
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

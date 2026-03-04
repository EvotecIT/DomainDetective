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
    public void Load_ThrowsWhenVersionLessThanOne() {
        var json = @"{ ""version"": 0, ""defaults"": {} }";

        var file = Path.GetTempFileName();
        try {
            File.WriteAllText(file, json);
            Assert.Throws<InvalidOperationException>(() => DesiredStateConfiguration.Load(file));
        } finally {
            File.Delete(file);
        }
    }

    [Fact]
    public void Load_ThrowsOnMalformedJson() {
        var json = @"{ ""version"": 1, ""defaults"": ";

        var file = Path.GetTempFileName();
        try {
            File.WriteAllText(file, json);
            Assert.ThrowsAny<System.Text.Json.JsonException>(() => DesiredStateConfiguration.Load(file));
        } finally {
            File.Delete(file);
        }
    }

    [Fact]
    public void ResolveProfile_AppliesMultipleOverridesInOrder_LastWins() {
        var cfg = new DesiredStateConfiguration {
            Defaults = new DesiredStateProfile {
                Spf = new DesiredStateSpfPolicy {
                    MaxDnsLookups = 10
                }
            },
            Overrides = new List<DesiredStateOverride> {
                new DesiredStateOverride {
                    Match = new DesiredStateMatch {
                        DomainPatterns = new[] { "*.example.com" }
                    },
                    Profile = new DesiredStateProfile {
                        Spf = new DesiredStateSpfPolicy {
                            MaxDnsLookups = 5
                        }
                    }
                },
                new DesiredStateOverride {
                    Match = new DesiredStateMatch {
                        DomainPatterns = new[] { "a.example.com" }
                    },
                    Profile = new DesiredStateProfile {
                        Spf = new DesiredStateSpfPolicy {
                            MaxDnsLookups = 3
                        }
                    }
                }
            }
        };

        var profile = cfg.ResolveProfile("a.example.com", classification: null);

        Assert.NotNull(profile.Spf);
        Assert.Equal(3, profile.Spf!.MaxDnsLookups);
    }

    [Fact]
    public void ResolveProfile_DoesNotApplyClassificationOverrideWhenClassificationMissing() {
        var cfg = new DesiredStateConfiguration {
            Defaults = new DesiredStateProfile {
                Spf = new DesiredStateSpfPolicy {
                    RequireDenyAll = false
                }
            },
            Overrides = new List<DesiredStateOverride> {
                new DesiredStateOverride {
                    Match = new DesiredStateMatch {
                        DomainPatterns = new[] { "*.example.com" },
                        Classifications = new[] { MailDomainClassificationCategory.Parked }
                    },
                    Profile = new DesiredStateProfile {
                        Spf = new DesiredStateSpfPolicy {
                            RequireDenyAll = true
                        }
                    }
                }
            }
        };

        var profile = cfg.ResolveProfile("a.example.com", classification: null);

        Assert.NotNull(profile.Spf);
        Assert.False(profile.Spf!.RequireDenyAll);
    }

    [Fact]
    public void ResolveProfile_AppliesClassificationOverrideWhenClassificationMatches() {
        var cfg = new DesiredStateConfiguration {
            Defaults = new DesiredStateProfile {
                Spf = new DesiredStateSpfPolicy {
                    RequireDenyAll = false
                }
            },
            Overrides = new List<DesiredStateOverride> {
                new DesiredStateOverride {
                    Match = new DesiredStateMatch {
                        DomainPatterns = new[] { "*.example.com" },
                        Classifications = new[] { MailDomainClassificationCategory.Parked }
                    },
                    Profile = new DesiredStateProfile {
                        Spf = new DesiredStateSpfPolicy {
                            RequireDenyAll = true
                        }
                    }
                }
            }
        };

        var profile = cfg.ResolveProfile("a.example.com", MailDomainClassificationCategory.Parked);

        Assert.NotNull(profile.Spf);
        Assert.True(profile.Spf!.RequireDenyAll);
    }

    [Fact]
    public void ResolveProfile_MatchesWildcardPatternsCaseInsensitive() {
        var cfg = new DesiredStateConfiguration {
            Defaults = new DesiredStateProfile(),
            Overrides = new List<DesiredStateOverride> {
                new DesiredStateOverride {
                    Match = new DesiredStateMatch {
                        DomainPatterns = new[] { "*.ExAmPle.CoM" }
                    },
                    Profile = new DesiredStateProfile {
                        Dmarc = new DesiredStateDmarcPolicy {
                            RequireRua = true
                        }
                    }
                }
            }
        };

        var profile = cfg.ResolveProfile("a.example.com", MailDomainClassificationCategory.SendingAndReceiving);

        Assert.NotNull(profile.Dmarc);
        Assert.True(profile.Dmarc!.RequireRua == true);
    }

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
    public async Task Evaluate_DmarcRuaDomainSuffixMatch_IsCaseInsensitive() {
        var health = new DomainHealthCheck();

        var record = "v=DMARC1; p=reject; rua=mailto:agg@reports.dmarc.powermarc.com";
        await health.CheckDMARC(record);

        var profile = new DesiredStateProfile {
            Dmarc = new DesiredStateDmarcPolicy {
                AllowedReportDomainSuffixes = new[] { "DMARC.POWERMARC.COM" },
                RequireRecord = true
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.DoesNotContain(result.Assessments, a =>
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

}

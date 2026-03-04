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
    public void Evaluate_TtlMtastsTxtUniformAcrossNsRequired_AddsWarning() {
        var health = new DomainHealthCheck();
        health.DnsTtlAnalysis.ServerTtlTxtMtasts["192.0.2.1"] = 300;
        health.DnsTtlAnalysis.ServerTtlTxtMtasts["192.0.2.2"] = 600;

        var profile = new DesiredStateProfile {
            Ttl = new DesiredStateTtlPolicy {
                RequireMtastsTxtUniformAcrossNs = true
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Warning &&
            string.Equals(a.Code, DesiredStateCodes.TtlMtastsTxtUniformityRequired, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Evaluate_TtlTlsRptTxtUniformAcrossNsRequired_AddsWarning() {
        var health = new DomainHealthCheck();
        health.DnsTtlAnalysis.ServerTtlTxtTlsRpt["192.0.2.1"] = 300;
        health.DnsTtlAnalysis.ServerTtlTxtTlsRpt["192.0.2.2"] = 600;

        var profile = new DesiredStateProfile {
            Ttl = new DesiredStateTtlPolicy {
                RequireTlsRptTxtUniformAcrossNs = true
            }
        };

        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile, MailDomainClassificationCategory.SendingAndReceiving);

        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, a =>
            a.Severity == AssessmentSeverity.Warning &&
            string.Equals(a.Code, DesiredStateCodes.TtlTlsRptTxtUniformityRequired, StringComparison.OrdinalIgnoreCase));
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

}

using DnsClientX;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

public class TestMailPolicyReviewContracts {
    [Fact]
    public async Task RepeatedMailAnalysisDoesNotRetainEarlierAbsenceClaims() {
        var (check, _) = Create();
        await check.VerifySPF("example.com");
        await check.CheckSPF("v=spf1 -all");
        Assert.DoesNotContain(check.SpfAnalysis.Assessments, a => a.Code == SpfCodes.MissingRecord);
        await check.VerifyDMARC("example.com");
        await check.CheckDMARC("v=DMARC1; p=reject");
        Assert.DoesNotContain(check.DmarcAnalysis.Assessments, a => a.Code == DmarcCodes.MissingRecord);
    }

    [Fact]
    public async Task RepeatedUnknownModifiersDoNotInvalidateSpf() {
        var (check, _) = Create();
        await check.CheckSPF("v=spf1 ip4:192.0.2.1 x=one x=two -all");
        Assert.False(check.SpfAnalysis.PermError);
        Assert.Equal("pass", (await Evaluate(check.SpfAnalysis)).Verdict);
    }

    [Fact]
    public async Task NoSpfRecordIsAbsenceWithoutPermanentError() {
        var (check, _) = Create();
        await check.VerifySPF("example.com");
        Assert.False(check.SpfAnalysis.SpfRecordExists);
        Assert.False(check.SpfAnalysis.PermError);
        Assert.Equal("none", (await Evaluate(check.SpfAnalysis)).Verdict);
    }

    [Fact]
    public async Task PublicSpfDiscoveryConcatenatesVersionAndExcludesUnrelatedTxt() {
        var (check, _) = Create(new() {
            [("example.com", DnsRecordType.TXT)] = new[] { Txt("\"v=sp\" \"f1 redirect=_spf.example.net\""), Txt("note=SPF1 is used elsewhere") },
            [("_spf.example.net", DnsRecordType.TXT)] = new[] { Txt("\"v=sp\" \"f1 ip4:192.0.2.1 -all\"") }
        });
        await check.VerifySPF("example.com");
        Assert.True(check.SpfAnalysis.SpfRecordExists);
        Assert.False(check.SpfAnalysis.MultipleSpfRecords);
        Assert.Equal("pass", (await Evaluate(check.SpfAnalysis)).Verdict);
        Assert.True(check.SpfAnalysis.EffectiveSpfSends);
    }

    [Fact]
    public async Task LegacyDmarcDiscoveryConcatenatesVersion() {
        var (check, _) = Create(new() { [("_dmarc.example.com", DnsRecordType.TXT)] = new[] { Txt("\"v=DMA\" \"RC1; p=reject\"") } });
        check.DmarcDiscoveryMode = DmarcDiscoveryMode.LegacyPublicSuffix;
        await check.VerifyDMARC("example.com");
        Assert.True(check.DmarcAnalysis.DmarcRecordExists);
        Assert.Equal("reject", check.DmarcAnalysis.EffectivePolicyShort);
    }

    [Fact]
    public async Task RetainedRedirectStillAuthorizesSending() {
        var (check, _) = Create();
        check.SpfAnalysis.TestSpfRecords["_spf.example.net"] = "v=spf1 ip4:192.0.2.1 -all";
        await check.CheckSPF("v=spf1 redirect=_spf.example.net");
        Assert.Equal("v=spf1 redirect=_spf.example.net", await check.SpfAnalysis.GetFlattenedSpf());
        await check.SpfAnalysis.ComputeEffectiveSpfSendsAsync();
        Assert.True(check.SpfAnalysis.EffectiveSpfSends);
        Assert.Equal("pass", (await Evaluate(check.SpfAnalysis)).Verdict);
    }

    [Theory]
    [InlineData("a/24//64", "_spf.example.net")]
    [InlineData("mx/24//64", "mail.example.net")]
    public async Task IncludedRelativeAddressMechanismsResolveDomainAndRetainCidr(string mechanism, string host) {
        var (check, queries) = Create(new() {
            [("_spf.example.net", DnsRecordType.MX)] = new[] { new DnsAnswer { Type = DnsRecordType.MX, DataRaw = "10 mail.example.net." } },
            [(host, DnsRecordType.A)] = new[] { new DnsAnswer { Type = DnsRecordType.A, DataRaw = "192.0.2.240" } },
            [(host, DnsRecordType.AAAA)] = new[] { new DnsAnswer { Type = DnsRecordType.AAAA, DataRaw = "2001:db8::1" } }
        });
        check.SpfAnalysis.TestSpfRecords["_spf.example.net"] = "v=spf1 +" + mechanism + " -all";
        await check.CheckSPF("v=spf1 include:_spf.example.net -all");
        var result = await check.SpfAnalysis.GetFlattenedIpAnalysis("example.com");
        Assert.Contains("192.0.2.240/24", result.UniqueIps);
        Assert.Contains("2001:db8::1/64", result.UniqueIps);
        Assert.DoesNotContain(queries, query => query.Name.Contains('/'));
    }

    [Theory]
    [InlineData("v=spf1 -all include:_loop.example.net")]
    [InlineData("v=spf1 redirect=_loop.example.net -all")]
    public async Task UnreachableDnsDependenciesDoNotInvalidateDenyAll(string policy) {
        var (check, queries) = Create(new() { [("_loop.example.net", DnsRecordType.TXT)] = new[] { Txt("v=spf1 include:_loop.example.net -all") } });
        await check.CheckSPF(policy);
        await check.SpfAnalysis.GetFlattenedSpfTree();
        await check.SpfAnalysis.PopulateProvenanceAsync("example.com");
        Assert.False(check.SpfAnalysis.PermError);
        Assert.True(check.SpfAnalysis.DenyAll);
        Assert.Equal(0, check.SpfAnalysis.DnsLookupsCount);
        Assert.Empty(queries);
        Assert.Equal("fail", (await Evaluate(check.SpfAnalysis)).Verdict);
    }

    [Theory]
    [InlineData("include:broken}")]
    [InlineData("include:%%{d}")]
    public async Task LiteralClosingBraceDoesNotMasqueradeAsTerminalMacro(string term) {
        var (check, _) = Create();
        await check.CheckSPF("v=spf1 ip4:192.0.2.1 " + term + " -all");
        Assert.True(check.SpfAnalysis.PermError);
        Assert.Equal("permerror", (await Evaluate(check.SpfAnalysis)).Verdict);
    }

    [Theory]
    [InlineData("none", "reject", "n", "reject", false)]
    [InlineData("reject", "quarantine", "y", "none", true)]
    public async Task InheritedDmarcPostureUsesEffectiveSubdomainPolicy(string published, string sub, string test, string effective, bool weak) {
        var (check, _) = Create(new() { [("_dmarc.example.com", DnsRecordType.TXT)] = new[] { Txt($"v=DMARC1; p={published}; sp={sub}; t={test}; psd=n") } });
        await check.VerifyDMARC("mail.example.com");
        Assert.Equal(published, check.DmarcAnalysis.PolicyShort);
        Assert.Equal(effective, check.DmarcAnalysis.EffectivePolicyShort);
        Assert.Equal(weak, check.DmarcAnalysis.WeakPolicy);
        Assert.Equal(effective, DomainDetective.Views.Converters.Convert(check.DmarcAnalysis).EffectivePolicy);
        Assert.DoesNotContain(check.DmarcAnalysis.Assessments, assessment =>
            effective != "reject" && assessment.Code == DmarcCodes.PolicyReject || effective != "quarantine" && assessment.Code == DmarcCodes.PolicyQuarantine);
    }

    [Fact]
    public async Task DirectDmarcTestModeDoesNotClaimRejectInEffect() {
        var (check, _) = Create();
        await check.CheckDMARC("v=DMARC1; p=reject; t=y");
        Assert.Equal("quarantine", check.DmarcAnalysis.EffectivePolicyShort);
        Assert.Contains("quarantine", check.DmarcAnalysis.Advisory);
        Assert.DoesNotContain(check.DmarcAnalysis.Assessments, assessment => assessment.Code == DmarcCodes.PolicyReject);
    }

    [Theory]
    [InlineData("")]
    [InlineData("; pct=100")]
    public async Task LegacyPercentageDoesNotClaimEnforcementInTestMode(string percent) {
        var (check, _) = Create();
        await check.CheckDMARC("v=DMARC1; p=quarantine; t=y" + percent);
        Assert.Equal("none", check.DmarcAnalysis.EffectivePolicyShort);
        Assert.DoesNotContain(check.DmarcAnalysis.Assessments, a => a.Message.Contains("full enforcement"));
        Assert.Equal(percent.Length > 0, check.DmarcAnalysis.Assessments.Any(a => a.Code == DmarcCodes.Percent100));
        Assert.DoesNotContain(DomainDetective.Narratives.DmarcNarrative.Build(check.DmarcAnalysis).Highlights,
            text => text.Contains("full enforcement"));
    }

    [Fact]
    public async Task TestModeDmarcDoesNotSuppressMissingWildcardSpfWarning() {
        var (check, _) = Create(new() {
            [("_dmarc.example.com", DnsRecordType.TXT)] = new[] { Txt("v=DMARC1; p=reject; t=y") },
            [("example.com", DnsRecordType.TXT)] = new[] { Txt("v=spf1 -all") }
        });
        await check.VerifyDMARC("example.com");
        await check.VerifySPF("example.com");
        Assert.Equal("quarantine", check.DmarcAnalysis.EffectiveSubdomainPolicyShort);
        Assert.Contains(check.SpfAnalysis.Assessments, a => a.Code == SpfCodes.WildcardMissing);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DiscardedDmarcRecordsRetainDiagnosticEvidence(bool duplicateTag) {
        var answers = duplicateTag ? new[] { Txt("v=DMARC1; p=reject; p=none") } : new[] { Txt("v=DMARC1; p=reject"), Txt("v=DMARC1; p=none") };
        var (check, _) = Create(new() { [("_dmarc.example.com", DnsRecordType.TXT)] = answers });
        await check.VerifyDMARC("example.com");
        Assert.True(check.DmarcAnalysis.DmarcRecordExists);
        Assert.Equal(!duplicateTag, check.DmarcAnalysis.MultipleRecords);
        Assert.Empty(check.DmarcAnalysis.EffectivePolicyShort);
        Assert.DoesNotContain(check.DmarcAnalysis.Assessments, a => a.Code == DmarcCodes.MissingRecord);
    }

    [Fact]
    public async Task ExactDmarcPolicyNeedsNoAuxiliaryWalkWithoutReporting() {
        var (check, queries) = Create();
        check.DnsConfiguration.QueryDnsResponseOverride = (name, type, _) => {
            queries.Add((name, type));
            return Task.FromResult(name == "_dmarc.example.com"
                ? new DnsResponse { Status = DnsResponseCode.NoError, Answers = new[] { Txt("v=DMARC1; p=reject") } }
                : new DnsResponse { Status = DnsResponseCode.ServerFailure });
        };
        await check.VerifyDMARC("example.com");
        Assert.True(check.DmarcAnalysis.DmarcRecordExists);
        Assert.Equal("reject", check.DmarcAnalysis.EffectivePolicyShort);
        Assert.False(check.DmarcAnalysis.DnsQueryFailed);
        Assert.Single(queries);
    }

    [Fact]
    public async Task ReportingFailurePreservesKnownDmarcPolicyAndDoesNotInventAuthorizationAbsence() {
        var (check, _) = Create();
        check.DnsConfiguration.QueryDnsResponseOverride = (name, _, _) => Task.FromResult(name == "_dmarc.example.com"
            ? new DnsResponse { Status = DnsResponseCode.NoError, Answers = new[] { Txt("v=DMARC1; p=reject; psd=n; rua=mailto:reports@example.net") } }
            : new DnsResponse { Status = DnsResponseCode.ServerFailure });
        await check.VerifyDMARC("example.com");
        Assert.True(check.DmarcAnalysis.DmarcRecordExists);
        Assert.Equal("reject", check.DmarcAnalysis.EffectivePolicyShort);
        Assert.False(check.DmarcAnalysis.DnsQueryFailed);
        Assert.True(check.DmarcAnalysis.ReportingQueryFailed);
        Assert.False(check.DmarcAnalysis.ExternalReportAuthorization.ContainsKey("example.net"));
        Assert.DoesNotContain(check.DmarcAnalysis.Assessments, a => a.Code == DmarcCodes.MissingRecord);
    }

    [Fact]
    public async Task RejectedAuthorRecordsDoNotBlockValidInheritedDmarcPolicy() {
        var (check, _) = Create(new() {
            [("_dmarc.mail.example.com", DnsRecordType.TXT)] = new[] { Txt("v=DMARC1; p=reject"), Txt("v=DMARC1; p=none") },
            [("_dmarc.example.com", DnsRecordType.TXT)] = new[] { Txt("v=DMARC1; p=reject; psd=n") }
        });
        await check.VerifyDMARC("mail.example.com");
        Assert.Equal("example.com", check.DmarcAnalysis.PolicyDomain);
        Assert.False(check.DmarcAnalysis.MultipleRecords);
        Assert.Equal("reject", check.DmarcAnalysis.EffectivePolicyShort);
        Assert.Contains(check.DmarcAnalysis.Assessments, a => a.Code == DmarcCodes.MultipleRecords && a.Message.Contains("mail.example.com"));
    }

    [Theory]
    [InlineData(DnsResponseCode.NoError, "none", true)]
    [InlineData(DnsResponseCode.NXDomain, "reject", false)]
    [InlineData(DnsResponseCode.ServerFailure, "", null)]
    public async Task NonexistentPolicyRequiresAuthorDomainEvidence(DnsResponseCode status, string effective, bool? exists) {
        var (check, _) = Create();
        check.DnsConfiguration.QueryDnsResponseOverride = (name, type, _) => Task.FromResult(name == "_dmarc.example.com"
            ? new DnsResponse { Status = DnsResponseCode.NoError, Answers = new[] { Txt("v=DMARC1; p=quarantine; sp=none; np=reject; psd=n") } }
            : new DnsResponse { Status = name == "mail.example.com" && type == DnsRecordType.SOA ? status : DnsResponseCode.NoError });
        await check.VerifyDMARC("mail.example.com");
        Assert.True(check.DmarcAnalysis.DmarcRecordExists);
        Assert.Equal("example.com", check.DmarcAnalysis.PolicyDomain);
        Assert.Equal(effective, check.DmarcAnalysis.EffectivePolicyShort);
        Assert.Equal(exists, check.DmarcAnalysis.SubjectDomainExists);
        Assert.Equal(status == DnsResponseCode.ServerFailure, check.DmarcAnalysis.DnsQueryFailed);
        Assert.DoesNotContain(check.DmarcAnalysis.Assessments, a => a.Code == DmarcCodes.MissingRecord);
    }

    private static DnsAnswer Txt(string text) => new() { Type = DnsRecordType.TXT, DataRaw = text };
    private static Task<SpfHostEvaluation> Evaluate(SpfAnalysis analysis) => analysis.EvaluateHostAsync("example.com", IPAddress.Parse("192.0.2.1"), "sender@example.com", "mail.example.com");
    private static (DomainHealthCheck Check, List<(string Name, DnsRecordType Type)> Queries) Create(Dictionary<(string, DnsRecordType), DnsAnswer[]>? records = null) {
        var queries = new List<(string, DnsRecordType)>();
        var check = new DomainHealthCheck();
        check.DnsConfiguration.QueryDnsOverride = (name, type) => {
            queries.Add((name, type));
            return Task.FromResult(records != null && records.TryGetValue((name, type), out var answers) ? answers : Array.Empty<DnsAnswer>());
        };
        return (check, queries);
    }
}

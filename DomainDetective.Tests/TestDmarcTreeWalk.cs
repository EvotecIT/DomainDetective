using DnsClientX;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

public class TestDmarcTreeWalk {
    [Fact]
    public async Task ExplicitOrganizationalBoundarySelectsIntermediatePolicy() {
        var records = new Dictionary<string, string> {
            ["mail.example.com"] = "v=DMARC1; p=none; sp=reject; psd=n",
            ["example.com"] = "v=DMARC1; p=none"
        };
        var (check, queries) = Create(records);
        await check.VerifyDMARC("a.mail.example.com");
        Assert.Equal("mail.example.com", check.DmarcAnalysis.PolicyDomain);
        Assert.Equal("mail.example.com", check.DmarcAnalysis.OrganizationalDomain);
        Assert.False(check.DmarcAnalysis.WeakPolicy);
        Assert.DoesNotContain("_dmarc.example.com", queries);
    }

    [Fact]
    public async Task WithoutBoundaryFewestLabelPolicyDefinesOrganization() {
        var (check, _) = Create(new Dictionary<string, string> {
            ["mail.example.com"] = "v=DMARC1; p=reject",
            ["example.com"] = "v=DMARC1; p=none"
        });
        await check.VerifyDMARC("a.mail.example.com");
        Assert.Equal("example.com", check.DmarcAnalysis.PolicyDomain);
        Assert.Equal("example.com", check.DmarcAnalysis.OrganizationalDomain);
    }

    [Theory]
    [InlineData(false, "bank.example")]
    [InlineData(true, "giant.bank.example")]
    public async Task PsdPolicyOnlyAppliesWhenOrganizationHasNoPolicy(bool organizationPolicy, string expected) {
        var records = new Dictionary<string, string> { ["bank.example"] = "v=DMARC1; p=reject; psd=y" };
        if (organizationPolicy) records["giant.bank.example"] = "v=DMARC1; p=none";
        var (check, _) = Create(records);
        await check.VerifyDMARC("mail.giant.bank.example");
        Assert.Equal(expected, check.DmarcAnalysis.PolicyDomain);
        Assert.Equal("giant.bank.example", check.DmarcAnalysis.OrganizationalDomain);
    }

    [Fact]
    public async Task LongNamesUseAtMostEightQueries() {
        var (check, queries) = Create(new Dictionary<string, string>());
        await check.VerifyDMARC("a.b.c.d.e.f.g.h.i.j.mail.example.com");
        Assert.Equal(new[] {
            "_dmarc.a.b.c.d.e.f.g.h.i.j.mail.example.com", "_dmarc.g.h.i.j.mail.example.com",
            "_dmarc.h.i.j.mail.example.com", "_dmarc.i.j.mail.example.com", "_dmarc.j.mail.example.com",
            "_dmarc.mail.example.com", "_dmarc.example.com", "_dmarc.com"
        }, queries);
    }

    [Fact]
    public async Task LegacyDiscoveryRemainsExplicitlyAvailable() {
        var (check, queries) = Create(new Dictionary<string, string> {
            ["mail.example.com"] = "v=DMARC1; p=reject; psd=n",
            ["example.com"] = "v=DMARC1; p=none"
        });
        check.DmarcDiscoveryMode = DmarcDiscoveryMode.LegacyPublicSuffix;
        await check.VerifyDMARC("a.mail.example.com");
        Assert.Equal("example.com", check.DmarcAnalysis.PolicyDomain);
        Assert.Equal(new[] { "_dmarc.a.mail.example.com", "_dmarc.example.com" }, queries);
    }

    [Fact]
    public async Task OperationalFailureStopsInheritance() {
        var (check, queries) = Create(new Dictionary<string, string> { ["example.com"] = "v=DMARC1; p=reject" });
        check.DnsConfiguration.QueryDnsResponseOverride = (name, _, _) => {
            queries.Add(name);
            return Task.FromResult(new DnsResponse { Status = DnsResponseCode.ServerFailure });
        };
        await check.VerifyDMARC("a.mail.example.com");
        Assert.Single(queries);
        Assert.True(check.DmarcAnalysis.DnsQueryFailed);
        Assert.False(check.DmarcAnalysis.DmarcRecordExists);
        Assert.DoesNotContain(check.DmarcAnalysis.Assessments, a => a.Code == DmarcCodes.MissingRecord);
    }

    [Fact]
    public async Task AlignmentUsesPsdBoundariesForEachAuthenticatedDomain() {
        var (check, _) = Create(new Dictionary<string, string> {
            ["giant.bank.example"] = "v=DMARC1; p=none",
            ["bank.example"] = "v=DMARC1; p=reject; psd=y"
        });
        await check.VerifyDMARC("giant.bank.example");
        await check.DmarcAnalysis.EvaluateAlignmentAsync("giant.bank.example", "mail.giant.bank.example", "mail.mega.bank.example");
        Assert.True(check.DmarcAnalysis.SpfAligned);
        Assert.False(check.DmarcAnalysis.DkimAligned);
    }

    [Fact]
    public async Task StrictAlignmentDoesNotNeedAnOrganizationalWalk() {
        var (check, queries) = Create(new Dictionary<string, string>());
        await check.CheckDMARC("v=DMARC1; p=reject; adkim=s; aspf=s");
        await check.DmarcAnalysis.EvaluateAlignmentAsync("mail.example.com", "example.com", "mail.example.com");
        Assert.False(check.DmarcAnalysis.SpfAligned);
        Assert.True(check.DmarcAnalysis.DkimAligned);
        Assert.Empty(queries);
    }

    [Theory]
    [InlineData("mailto:reports@mail.example.com")]
    [InlineData("mailto:reports@mail.example.com!10m")]
    [InlineData("https://mail.example.com/reports")]
    public async Task InvalidPolicyWithValidReportingFallsBackToNone(string reportUri) {
        var (check, _) = Create(new Dictionary<string, string> {
            ["mail.example.com"] = "v=DMARC1; p=reject; sp=invalid; rua=" + reportUri,
            ["example.com"] = "v=DMARC1; p=reject"
        });
        await check.VerifyDMARC("mail.example.com");
        Assert.Equal("mail.example.com", check.DmarcAnalysis.PolicyDomain);
        Assert.False(check.DmarcAnalysis.IsPolicyValid);
        Assert.Equal("none", check.DmarcAnalysis.EffectivePolicyShort);
        Assert.True(check.DmarcAnalysis.WeakPolicy);
    }

    [Fact]
    public async Task InvalidPolicyWithoutValidReportingDoesNotInherit() {
        var (check, _) = Create(new Dictionary<string, string> {
            ["mail.example.com"] = "v=DMARC1; p=invalid; rua=mailto:not-an-address",
            ["example.com"] = "v=DMARC1; p=reject"
        });
        await check.VerifyDMARC("mail.example.com");
        Assert.Equal("mail.example.com", check.DmarcAnalysis.PolicyDomain);
        Assert.False(check.DmarcAnalysis.IsPolicyValid);
        Assert.Empty(check.DmarcAnalysis.EffectivePolicyShort);
        Assert.True(check.DmarcAnalysis.InvalidReportUri);
    }

    [Theory]
    [InlineData("reject", "quarantine")]
    [InlineData("quarantine", "none")]
    [InlineData("none", "none")]
    public async Task TestModeReducesEnforcementByOneLevel(string published, string effective) {
        var (check, _) = Create(new Dictionary<string, string>());
        await check.CheckDMARC("v=DMARC1; p=" + published + "; t=y");
        Assert.True(check.DmarcAnalysis.IsTestMode);
        Assert.Equal(published, check.DmarcAnalysis.PolicyShort);
        Assert.Equal(effective, check.DmarcAnalysis.EffectivePolicyShort);
        await check.CheckDMARC("v=DMARC1; p=reject");
        Assert.False(check.DmarcAnalysis.IsTestMode);
        Assert.Equal("reject", check.DmarcAnalysis.EffectivePolicyShort);
    }

    private static (DomainHealthCheck Check, List<string> Queries) Create(Dictionary<string, string> records) {
        var queries = new List<string>();
        var check = new DomainHealthCheck();
        check.DnsConfiguration.QueryDnsOverride = (name, type) => {
            queries.Add(name);
            return Task.FromResult(type == DnsRecordType.TXT && name.StartsWith("_dmarc.")
                && records.TryGetValue(name.Substring(7), out var record)
                ? new[] { new DnsAnswer { Name = name, Type = type, DataRaw = record } }
                : Array.Empty<DnsAnswer>());
        };
        return (check, queries);
    }
}

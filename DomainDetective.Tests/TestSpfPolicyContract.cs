using DnsClientX;
using System.Net;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

public class TestSpfPolicyContract {
    [Theory]
    [InlineData("v=spf1 +all -all", false, "pass")]
    [InlineData("v=spf1 -all +all", true, "fail")]
    [InlineData("v=spf1 x=ignored -all ip4:192.0.2.1", true, "fail")]
    public async Task FirstAllControlsDenyAllAndEvaluation(string record, bool denyAll, string expected) {
        var check = Create();
        await check.CheckSPF(record);
        Assert.Equal(denyAll, check.SpfAnalysis.DenyAll);
        Assert.Equal(expected, (await Evaluate(check.SpfAnalysis)).Verdict);
    }

    [Theory]
    [InlineData("v=spf1 ip4:192.0.2.1 bogus -all")]
    [InlineData("v=spf1 +all ip4:192.0.2.0/33")]
    [InlineData("v=spf1 ip4:192.0.2.1 +redirect=example.net -all")]
    [InlineData("v=spf1 ++ip4:192.0.2.1 -all")]
    [InlineData("v=spf1 ip4:192.0.2.1 exists:%{z}.example.net -all")]
    public async Task CompleteSyntaxIsValidatedBeforeAnyMatch(string record) {
        var check = Create();
        await check.CheckSPF(record);
        Assert.True(check.SpfAnalysis.PermError);
        Assert.Equal("permerror", (await Evaluate(check.SpfAnalysis)).Verdict);
        Assert.False(check.SpfAnalysis.DenyAll);
    }

    [Fact]
    public async Task UnknownModifierIsIgnored() {
        var check = Create();
        await check.CheckSPF("v=spf1 ip4:192.0.2.1 x=unknown -all");
        Assert.False(check.SpfAnalysis.PermError);
        Assert.Empty(check.SpfAnalysis.UnknownMechanisms);
        Assert.Equal("pass", (await Evaluate(check.SpfAnalysis)).Verdict);
    }

    [Fact]
    public async Task MacroDelimitersDoNotBecomeCidrSeparators() {
        var check = Create();
        check.DnsConfiguration.QueryDnsOverride = (name, type) => Task.FromResult(
            name == "sender.part.example.net" && type == DnsRecordType.A
                ? new[] { new DnsAnswer { Type = type, DataRaw = "192.0.2.240" } }
                : Array.Empty<DnsAnswer>());
        await check.CheckSPF("v=spf1 a:%{l/}.example.net/24//64 -all");
        Assert.False(check.SpfAnalysis.PermError);
        var result = await check.SpfAnalysis.EvaluateHostAsync("example.com", IPAddress.Parse("192.0.2.1"),
            "sender/part@example.com", "mail.example.com");
        Assert.Equal("pass", result.Verdict);
    }

    [Fact]
    public async Task TxtStringsAreConcatenatedWithoutWhitespace() {
        var check = Create();
        await check.SpfAnalysis.AnalyzeSpfRecords(new[] {
            new DnsAnswer { Type = DnsRecordType.TXT, DataRaw = "\"v=spf1 ip4:192.0.2.\" \"1 -all\"" }
        }, new InternalLogger());
        Assert.Equal("v=spf1 ip4:192.0.2.1 -all", check.SpfAnalysis.SpfRecord);
        Assert.False(check.SpfAnalysis.PermError);
        Assert.Equal("pass", (await Evaluate(check.SpfAnalysis)).Verdict);
    }

    [Theory]
    [InlineData(DnsResponseCode.ServerFailure)]
    [InlineData(DnsResponseCode.Refused)]
    public async Task DnsFailureIsNotPolicyAbsence(DnsResponseCode code) {
        var check = Create();
        check.DnsConfiguration.QueryDnsResponseOverride = (_, _, _) => Task.FromResult(new DnsResponse { Status = code });
        Assert.Equal("temperror", (await Evaluate(check.SpfAnalysis)).Verdict);
        await check.VerifySPF("example.com");
        Assert.True(check.SpfAnalysis.DnsQueryFailed);
        Assert.Equal(code, check.SpfAnalysis.DnsQueryResponseCode);
        Assert.Equal("temperror", (await Evaluate(check.SpfAnalysis)).Verdict);
        Assert.DoesNotContain(check.SpfAnalysis.Assessments, assessment => assessment.Code == SpfCodes.MissingRecord);
    }

    [Fact]
    public async Task IncludedRelativeMechanismsKeepTheirDomain() {
        var check = Create();
        check.SpfAnalysis.TestSpfRecords["_spf.example.net"] = "v=spf1 a mx/24 -all";
        await check.CheckSPF("v=spf1 include:_spf.example.net -all");
        Assert.Equal("v=spf1 a:_spf.example.net mx:_spf.example.net/24 -all", await check.SpfAnalysis.GetFlattenedSpf());
        Assert.True(check.SpfAnalysis.FlatteningComplete);
    }

    [Theory]
    [InlineData("v=spf1 -ip4:192.0.2.1 +all", "include:_spf.example.net")]
    [InlineData("v=spf1 a:%{d} -all", "include:_spf.example.net")]
    [InlineData("v=spf1 ip4:192.0.2.1 -all", "-include:_spf.example.net")]
    public async Task UnsupportedIncludeConditionsRetainOriginalMeaning(string child, string include) {
        var check = Create();
        check.SpfAnalysis.TestSpfRecords["_spf.example.net"] = child;
        string original = "v=spf1 " + include + " -all";
        await check.CheckSPF(original);
        Assert.Equal(original, await check.SpfAnalysis.GetFlattenedSpf());
        Assert.False(check.SpfAnalysis.FlatteningComplete);
        Assert.NotEmpty(check.SpfAnalysis.FlatteningLimitations);
    }

    [Fact]
    public async Task RedirectDoesNotDiscardEarlierMechanisms() {
        var check = Create();
        check.SpfAnalysis.TestSpfRecords["_spf.example.net"] = "v=spf1 -all";
        string original = "v=spf1 ip4:192.0.2.1 redirect=_spf.example.net";
        await check.CheckSPF(original);
        Assert.Equal(original, await check.SpfAnalysis.GetFlattenedSpf());
        Assert.False(check.SpfAnalysis.FlatteningComplete);
    }

    private static DomainHealthCheck Create() {
        var check = new DomainHealthCheck();
        check.DnsConfiguration.QueryDnsOverride = (_, _) => Task.FromResult(Array.Empty<DnsAnswer>());
        return check;
    }

    private static Task<SpfHostEvaluation> Evaluate(SpfAnalysis analysis) => analysis.EvaluateHostAsync(
        "example.com", IPAddress.Parse("192.0.2.1"), "sender@example.com", "mail.example.com");
}

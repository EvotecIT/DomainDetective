namespace DomainDetective.Tests;

public class TestMessageHeaderPolicy {
    [Theory]
    [InlineData("test", "test", "QUFB", "QUFBQUFB", true)]
    [InlineData("test", "test", "QUFBQUFB", "QUFB", true)]
    [InlineData("test", "test", "QUFBQUFB", "QUFBQkJC", false)]
    [InlineData("test", "test", "QUFB", "quFB", false)]
    [InlineData("first", "second", "", "QUFB", false)]
    [InlineData("", "second", "QUFB", "QUFBQUFB", true)]
    [InlineData("test", "test", "", "QkJC", true)]
    public void ConflictRequiresCompatibleSelectorAndOverlappingPrefix(string firstSelector, string secondSelector, string firstPrefix, string secondPrefix, bool conflict) {
        string Properties(string selector, string prefix) => " header.d=example.com"
            + (selector.Length == 0 ? "" : " header.s=" + selector) + (prefix.Length == 0 ? "" : " header.b=" + prefix);
        var analysis = new MessageHeaderAnalysis();
        analysis.Parse("From: sender@example.com\r\nAuthentication-Results: mx.example; dkim=pass" + Properties(firstSelector, firstPrefix)
            + "; dkim=fail" + Properties(secondSelector, secondPrefix) + "\r\n",
            new MessageHeaderAnalysisOptions { TrustedAuthServIds = new[] { "mx.example" } });
        Assert.Equal(conflict, analysis.AuthenticationConflict);
        Assert.Equal(conflict ? "ambiguous" : "pass", analysis.DkimResult);
    }

    [Fact]
    public void ManyEquivalentObservationsRemainConsistentWithinTheHeaderLimit() {
        string repeated = string.Concat(Enumerable.Repeat("; dkim=pass header.d=example.com header.s=test header.b=QUFB", 10000));
        var analysis = new MessageHeaderAnalysis();
        analysis.Parse("From: sender@example.com\r\nAuthentication-Results: mx.example" + repeated + "\r\n",
            new MessageHeaderAnalysisOptions { TrustedAuthServIds = new[] { "mx.example" } });
        Assert.Equal(10000, Assert.Single(analysis.AuthenticationResults).Methods.Count);
        Assert.False(analysis.AuthenticationConflict);
        Assert.Equal("pass", analysis.DkimResult);
    }
    [Fact]
    public void LongObservationPrefixRemainsWithinTheHeaderContract() {
        string prefix = new string('A', 1024 * 1024);
        var analysis = new MessageHeaderAnalysis();
        analysis.Parse("From: sender@example.com\r\nAuthentication-Results: mx.example; dkim=pass header.d=example.com header.b=" + prefix + "\r\n",
            new MessageHeaderAnalysisOptions { TrustedAuthServIds = new[] { "mx.example" } });
        Assert.Single(Assert.Single(analysis.AuthenticationResults).Methods);
        Assert.False(analysis.AuthenticationConflict);
        Assert.Equal("pass", analysis.DkimResult);
    }

    [Fact]
    public void EncodedWordsCannotCreateTrustedAuthenticationProvenance() {
        var analysis = new MessageHeaderAnalysis();
        analysis.Parse("From: Sender <sender@example.com>\r\nSubject: =?utf-8?Q?Human_subject?=\r\n" +
            "Authentication-Results: =?utf-8?Q?mx.example?=;\r\n\tdkim=pass header.d=example.com\r\n",
            new MessageHeaderAnalysisOptions { TrustedAuthServIds = new[] { "mx.example" } });
        var evidence = Assert.Single(analysis.AuthenticationResults);
        Assert.NotEqual(MessageAuthenticationTrust.Configured, evidence.Trust);
        Assert.Contains("=?utf-8?Q?mx.example?=", evidence.Raw);
        Assert.Contains("\r\n\t", analysis.Fields.Single(field => field.Name == "Authentication-Results").RawValue);
        Assert.Equal("Human subject", analysis.Subject);
    }

    [Theory]
    [InlineData("b = YWJj")]
    [InlineData("b\t=\tYW Jj")]
    public void SignatureEncodingDiagnosticAcceptsLegalTagWhitespace(string tag) {
        var analysis = new MessageHeaderAnalysis();
        analysis.Parse("From: sender@example.com\r\nDKIM-Signature: d=example.com; s=test; h=from; " + tag + "\r\n");
        Assert.Empty(analysis.InvalidDkimSignatures);
        Assert.DoesNotContain(MessageHeaderIssue.InvalidDkim, analysis.Issues);
    }

    [Theory]
    [InlineData("QUFBQUFB", "QkJCQkJC")]
    [InlineData("QUFBQUFB", "quFBQUFB")]
    public void SignaturePrefixesDistinguishOtherwiseIdenticalSigners(string first, string second) {
        var analysis = new MessageHeaderAnalysis();
        analysis.Parse("From: sender@example.com\r\n" +
            $"DKIM-Signature: d=example.com; s=test; h=from; b={first}\r\n" +
            $"DKIM-Signature: d=example.com; s=test; h=from; b={second}\r\n" +
            $"Authentication-Results: mx.example; dkim=pass header.d=example.com header.s=test header.b={first}; dkim=fail header.d=example.com header.s=test header.b={second}\r\n",
            new MessageHeaderAnalysisOptions { TrustedAuthServIds = new[] { "mx.example" } });
        Assert.False(analysis.AuthenticationConflict);
        Assert.Equal(new[] { "pass", "fail" }, analysis.DkimSignatures.Select(signature => signature.ReceiverResult));
        Assert.Equal("Strict", analysis.DkimAlignment);
    }

    [Fact]
    public void MissingSignatureDiscriminatorRetainsAttributionAmbiguity() {
        var analysis = new MessageHeaderAnalysis();
        analysis.Parse("From: sender@example.com\r\n" +
            "DKIM-Signature: d=example.com; s=test; h=from; b=QUFBQUFB\r\n" +
            "DKIM-Signature: d=example.com; s=test; h=from; b=QkJCQkJC\r\n" +
            "Authentication-Results: mx.example; dkim=pass header.d=example.com header.s=test\r\n");
        Assert.All(analysis.DkimSignatures, signature => Assert.Equal("ambiguous", signature.ReceiverResult));
    }

    [Theory]
    [InlineData("bücher.com", "xn--bcher-kva.com", "test", "test")]
    [InlineData("example.com", "example.com", "bücher", "xn--bcher-kva")]
    public void InternationalizedIdentitiesHaveOneConflictBoundary(string firstDomain, string secondDomain, string firstSelector, string secondSelector) {
        var analysis = new MessageHeaderAnalysis();
        analysis.Parse($"From: sender@{secondDomain}\r\n" +
            $"DKIM-Signature: d={secondDomain}; s={secondSelector}; h=from; b=QUFBQUFB\r\n" +
            $"Authentication-Results: mx.example; dkim=pass header.d={firstDomain} header.s={firstSelector} header.b=QUFB; dkim=fail header.d={secondDomain} header.s={secondSelector} header.b=QUFB\r\n",
            new MessageHeaderAnalysisOptions { TrustedAuthServIds = new[] { "mx.example" } });
        Assert.True(analysis.AuthenticationConflict);
        Assert.Equal("ambiguous", analysis.DkimResult);
        Assert.Equal("conflict", Assert.Single(analysis.DkimSignatures).ReceiverResult);
        Assert.NotEqual("Strict", analysis.DkimAlignment);
    }
}

namespace DomainDetective.Tests;

public class TestMessageHeaderPolicy {
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
}

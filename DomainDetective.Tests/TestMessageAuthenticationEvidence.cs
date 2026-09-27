namespace DomainDetective.Tests;

public class TestMessageAuthenticationEvidence {
    [Theory]
    [InlineData("mx.example")]
    [InlineData("other.example")]
    public void DkimMetadataUsesEverySelectedConfiguredObservation(string secondWriter) {
        var analysis = new MessageHeaderAnalysis();
        analysis.Parse("From: sender@example.com\r\nDKIM-Signature: d=example.com; s=test; h=from; b=abc\r\nAuthentication-Results: mx.example; spf=pass smtp.mailfrom=example.com\r\nAuthentication-Results: " + secondWriter + "; dkim=pass header.d=example.com header.s=test\r\n", new MessageHeaderAnalysisOptions { TrustedAuthServIds = new[] { "mx.example", "other.example" } });
        Assert.Equal("pass", analysis.DkimResult);
        Assert.Equal("pass", Assert.Single(analysis.DkimSignatures).ReceiverResult);
        Assert.Equal("Strict", analysis.DkimAlignment);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void OriginalAuthenticationCannotReplaceSelectedNormalObservation(bool configured) {
        var analysis = new MessageHeaderAnalysis();
        analysis.Parse("From: sender@example.com\r\nDKIM-Signature: d=example.com; s=test; h=from; b=abc\r\nAuthentication-Results-Original: mx.example; dkim=fail header.d=example.com; spf=fail smtp.mailfrom=example.com; dmarc=fail header.from=example.com\r\nAuthentication-Results: mx.example; dkim=pass header.d=example.com; spf=pass smtp.mailfrom=example.com; dmarc=pass header.from=example.com\r\n", new MessageHeaderAnalysisOptions { TrustedAuthServIds = configured ? new[] { "mx.example" } : Array.Empty<string>() });
        Assert.Equal("pass", analysis.DkimResult);
        Assert.Equal("pass", Assert.Single(analysis.DkimSignatures).ReceiverResult);
        Assert.Equal("Strict", analysis.DkimAlignment);
        Assert.False(analysis.AuthenticationConflict);
        Assert.Equal(2, analysis.AuthenticationResults.Count);
        Assert.Equal("pass", analysis.SpfResult);
        Assert.Equal("pass", analysis.DmarcResult);
    }

    [Theory]
    [InlineData("other.example")]
    [InlineData("example.com")]
    public void DuplicateFromCannotEstablishAlignment(string firstDomain) {
        var analysis = new MessageHeaderAnalysis();
        analysis.Parse("From: sender@" + firstDomain + "\r\nfRoM: sender@example.com\r\nAuthentication-Results: mx.example; dkim=pass header.d=example.com; spf=pass smtp.mailfrom=example.com\r\n");
        Assert.Null(analysis.DkimAlignment);
        Assert.Null(analysis.SpfAlignment);
        Assert.Contains(analysis.Findings, finding => finding.Code == "HEADERS.Field.Duplicate");
    }

    [Fact]
    public void ConflictingDkimIdentityCannotEstablishAlignment() {
        var analysis = new MessageHeaderAnalysis();
        analysis.Parse("From: sender@example.com\r\nDKIM-Signature: d=example.com; s=test; h=from; b=abc\r\nAuthentication-Results: mx.example; dkim=pass header.d=example.com header.s=test\r\nAuthentication-Results: mx.example; dkim=fail header.d=example.com header.s=test\r\n", new MessageHeaderAnalysisOptions { TrustedAuthServIds = new[] { "mx.example" } });
        Assert.True(analysis.AuthenticationConflict);
        Assert.Equal("conflict", Assert.Single(analysis.DkimSignatures).ReceiverResult);
        Assert.Null(analysis.DkimAlignment);
    }

    [Theory]
    [InlineData("dkim=pass header.d=example.com; dkim=pass header.d=other.example", true)]
    [InlineData("dkim=pass header.d=example.com; i=1", false)]
    public void ArcAuthenticationHistoryAllowsRepeatedMethodsButRejectsRepeatedInstance(string methods, bool valid) {
        var analysis = new ARCAnalysis();
        analysis.Analyze("ARC-Seal: cv=none; i=1; d=example.com; b=abc\r\nARC-Message-Signature: d=example.com; i=1; b=abc\r\nARC-Authentication-Results: i=1; mx.example; " + methods + "\r\n");
        Assert.Equal(valid, analysis.ValidChain);
        if (valid) { Assert.Equal(2, Assert.Single(analysis.Instances).Authentication!.Methods.Count); }
        else { Assert.Contains(analysis.StructureIssues, issue => issue.Contains("repeats a tag")); }
    }

    [Fact]
    public void ArcSignatureTagsStillRejectDuplicateInstances() {
        var analysis = new ARCAnalysis();
        analysis.Analyze("ARC-Seal: i=1; i=1; cv=none; b=abc\r\nARC-Message-Signature: i=1; b=abc\r\nARC-Authentication-Results: i=1; mx.example; dkim=pass\r\n");
        Assert.False(analysis.ValidChain);
        Assert.Contains(analysis.StructureIssues, issue => issue.Contains("repeats a tag"));
    }

    [Theory]
    [InlineData("", true, "conflict", null)]
    [InlineData(" header.s=other", false, "pass", "Strict")]
    public void DkimConflictMatchingPreservesIndependentKnownSelectors(string secondSelector, bool conflict, string receiverResult, string? alignment) {
        var analysis = new MessageHeaderAnalysis();
        analysis.Parse("From: sender@example.com\r\nDKIM-Signature: d=example.com; s=test; h=from; b=abc\r\nAuthentication-Results: mx.example; dkim=pass header.d=example.com header.s=test; dkim=fail header.d=example.com" + secondSelector + "\r\n", new MessageHeaderAnalysisOptions { TrustedAuthServIds = new[] { "mx.example" } });
        Assert.Equal(conflict, analysis.AuthenticationConflict);
        Assert.Equal(receiverResult, Assert.Single(analysis.DkimSignatures).ReceiverResult);
        Assert.Equal(alignment, analysis.DkimAlignment);
    }

    [Fact]
    public void ExplicitTrustSelectsExactGatewayAndPreservesOtherClaims() {
        var analysis = new MessageHeaderAnalysis();
        analysis.Parse("Authentication-Results: attacker.example; dkim=pass header.d=example.com\r\nAuthentication-Results: mx.example; dkim=fail header.d=example.com; spf=pass smtp.mailfrom=example.com\r\n", new MessageHeaderAnalysisOptions { TrustedAuthServIds = new[] { "MX.EXAMPLE." } });
        Assert.Equal("fail", analysis.DkimResult);
        Assert.Equal("pass", analysis.SpfResult);
        Assert.Equal(MessageAuthenticationTrust.Configured, analysis.AuthenticationTrust);
        Assert.Equal(2, analysis.AuthenticationResults.Count);
        Assert.Equal("example.com", analysis.AuthenticationResults[1].Methods[0].Properties["header.d"]);
    }

    [Fact]
    public void RouteMatchAndSubdomainDoNotEstablishConfiguredTrust() {
        var analysis = new MessageHeaderAnalysis();
        analysis.Parse("Authentication-Results: attacker.mx.example; dkim=pass\r\nReceived: from sender.example by attacker.mx.example; Tue, 24 Oct 2023 12:34:56 +0000\r\n", new MessageHeaderAnalysisOptions { TrustedAuthServIds = new[] { "mx.example" } });
        Assert.Equal(MessageAuthenticationTrust.RouteMatched, analysis.AuthenticationTrust);
    }

    [Fact]
    public void CommentSemicolonsAndQuotedPropertiesDoNotCreateMethods() {
        var analysis = new MessageHeaderAnalysis();
        analysis.Parse("Authentication-Results: mx.example; dkim=fail (reason; dmarc=pass); spf=pass smtp.mailfrom=\"a;b@example.com\"; compauth=pass reason=100\r\n");
        Assert.Null(analysis.DmarcResult);
        Assert.Equal("fail", analysis.DkimResult);
        Assert.Equal("a;b@example.com", analysis.AuthenticationResults[0].Methods[1].Properties["smtp.mailfrom"]);
        Assert.Equal("100", analysis.CompAuthReason);
    }

    [Fact]
    public void ConflictingConfiguredResultsRemainVisible() {
        var analysis = new MessageHeaderAnalysis();
        analysis.Parse("Authentication-Results: mx.example; dmarc=fail\r\nAuthentication-Results: mx.example; dmarc=pass\r\n", new MessageHeaderAnalysisOptions { TrustedAuthServIds = new[] { "mx.example" } });
        Assert.True(analysis.AuthenticationConflict);
        Assert.Equal("fail", analysis.DmarcResult);
    }

    [Fact]
    public void MessageBodyCannotInjectHeaderFields() {
        var analysis = new MessageHeaderAnalysis();
        analysis.Parse("From: sender@example.com\r\n\r\nAuthentication-Results: mx.example; dmarc=pass");
        Assert.True(analysis.HadBody);
        Assert.Null(analysis.DmarcResult);
        Assert.Empty(analysis.AuthenticationResults);
    }

    [Fact]
    public void RouteOrderPreservesNegativeDelay() {
        var analysis = new MessageHeaderAnalysis();
        analysis.Parse("Received: from a.example by b.example; Tue, 24 Oct 2023 12:30:00 +0000\r\nReceived: from sender.example by a.example; Tue, 24 Oct 2023 12:34:56 +0000\r\n");
        Assert.True(analysis.HasClockSkew);
        Assert.Equal("a.example", analysis.ReceivedHops[1].FromHost);
        Assert.True(analysis.ReceivedHops[1].HopDelay < TimeSpan.Zero);
    }
}

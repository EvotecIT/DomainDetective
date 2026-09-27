namespace DomainDetective.Tests;

public class TestMessageAuthenticationEvidence {
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

namespace DomainDetective.Tests;

public class TestMessageEvidenceAmbiguity {
    [Theory]
    [InlineData("dkim=pass header.d=evil.example header.d=example.org", "dkim")]
    [InlineData("spf=pass smtp.mailfrom=evil.example smtp.mailfrom=example.org", "spf")]
    public void RepeatedPropertiesDoNotEstablishAlignment(string clause, string method) {
        var analysis = new MessageHeaderAnalysis();
        analysis.Parse("From: sender@example.org\r\nAuthentication-Results: mx.example; " + clause + "\r\n", new MessageHeaderAnalysisOptions { TrustedAuthServIds = new[] { "mx.example" } });
        Assert.True(analysis.AuthenticationConflict);
        Assert.Null(method == "spf" ? analysis.SpfAlignment : analysis.DkimAlignment);
        Assert.Contains(clause, analysis.AuthenticationResults[0].Raw);
    }

    [Fact]
    public void RepeatedReceivedSpfReceiverCannotSelectConfiguredTrust() {
        var analysis = new MessageHeaderAnalysis();
        analysis.Parse("From: sender@example.org\r\nReceived-SPF: pass; receiver=evil.example; receiver=mx.example; envelope-from=sender@example.org\r\n", new MessageHeaderAnalysisOptions { TrustedAuthServIds = new[] { "mx.example" } });
        Assert.NotEqual(MessageAuthenticationTrust.Configured, analysis.AuthenticationTrust);
        Assert.Null(analysis.SpfAlignment);
    }

    [Theory]
    [InlineData("Authentication-Results: mx.example; spf=pass smtp.mailfrom=example.org smtp.helo=helo.example\r\nAuthentication-Results: mx.example; spf=fail smtp.mailfrom=example.org")]
    [InlineData("Received-SPF: pass; receiver=mx.example; envelope-from=sender@example.org\r\nReceived-SPF: fail; receiver=mx.example; envelope-from=sender@example.org")]
    public void EquivalentSpfIdentitiesCannotHideConflictingResults(string headers) {
        var analysis = new MessageHeaderAnalysis();
        analysis.Parse("From: sender@example.org\r\n" + headers + "\r\n", new MessageHeaderAnalysisOptions { TrustedAuthServIds = new[] { "mx.example" } });
        Assert.True(analysis.AuthenticationConflict);
        Assert.Null(analysis.SpfAlignment);
    }

    [Theory]
    [InlineData("From: sender@example.org\r\nAuthentication-Results: mx.example; dmarc=fail header.from=example.org\r\nAuthentication-Results: mx.example; dmarc=pass header.from=example.org")]
    [InlineData("From: sender@evil.example\r\nFrom: sender@example.org\r\nAuthentication-Results: mx.example; dmarc=fail header.from=example.org")]
    public void AmbiguousEvidenceDoesNotEstablishSpoofDelivery(string headers) {
        var analysis = new MessageHeaderAnalysis();
        analysis.Parse(headers + "\r\nTo: recipient@example.org\r\nX-Microsoft-Antispam-Mailbox-Delivery: dest:I;\r\n", new MessageHeaderAnalysisOptions { TrustedAuthServIds = new[] { "mx.example" } });
        Assert.False(analysis.SelfSpoofDeliveredToInbox);
        if (analysis.AuthenticationConflict) { Assert.False(analysis.AuthenticationFailedDeliveredToInbox); }
        else { Assert.False(analysis.SameDomainSelfSpoof); }
    }
    [Theory]
    [InlineData("pass", "fail")]
    [InlineData("fail", "pass")]
    public void ConflictingSpfIdentityDoesNotEstablishAlignment(string first, string second) {
        var analysis = new MessageHeaderAnalysis();
        analysis.Parse($"From: sender@example.org\r\nAuthentication-Results: mx.example; spf={first} smtp.mailfrom=example.org\r\nAuthentication-Results: mx.example; spf={second} smtp.mailfrom=example.org\r\n", new MessageHeaderAnalysisOptions { TrustedAuthServIds = new[] { "mx.example" } });
        Assert.True(analysis.AuthenticationConflict);
        Assert.Null(analysis.SpfAlignment);
    }

    [Theory]
    [InlineData("other.example")]
    [InlineData("example.org")]
    public void DuplicateReturnPathDoesNotEstablishEnvelopeAlignment(string domain) {
        var analysis = new MessageHeaderAnalysis();
        analysis.Parse($"From: sender@example.org\r\nReturn-Path: <sender@{domain}>\r\nReturn-Path: <sender@example.org>\r\n");
        Assert.Null(analysis.SpfAlignment);
    }

    [Fact]
    public void TruncatedRouteDoesNotEstablishMxBypass() {
        var raw = "From: sender@example.org\r\nX-MS-Exchange-Organization-AuthAs: Anonymous\r\nX-Forefront-Antispam-Report: CIP:203.0.113.20;H:sender.example.org\r\nReceived: from internal.example by tenant.mail.protection.outlook.com with ESMTP\r\nReceived: from expected.example.org by internal.example with ESMTP\r\n";
        var analysis = new MessageHeaderAnalysis();
        analysis.Parse(raw, new MessageHeaderAnalysisOptions { MaximumReceivedHops = 1 });
        analysis.CompareExpectedMx(new[] { "expected.example.org" });
        Assert.Equal(1, analysis.OmittedReceivedHops);
        Assert.False(analysis.ExpectedMxBypassed);
        Assert.DoesNotContain(analysis.Assessments, a => a.Code == "HEADERS.Route.ExpectedMxBypassed");
        analysis.Parse(raw, new MessageHeaderAnalysisOptions { MaximumReceivedHops = 2 });
        analysis.CompareExpectedMx(new[] { "absent.example.org" });
        Assert.True(analysis.ExpectedMxBypassed);
    }

    [Theory]
    [InlineData("ESMTPA", "TLSv1.3", "TlsAuthenticated")]
    [InlineData("LMTPA", "TLSv1.2", "TlsAuthenticated")]
    [InlineData("ESMTPA", "", "Authenticated")]
    [InlineData("ESMTPSA", "", "TlsAuthenticated")]
    [InlineData("ESMTP", "TLSv1.3", "Tls")]
    public void TransportPreservesAuthenticationWithSeparateTls(string protocol, string tls, string expected) {
        var hop = ReceivedHop.Parse($"from sender.example by receiver.example with {protocol} ({tls})");
        Assert.Equal(expected, hop.ProtocolClass);
    }
}

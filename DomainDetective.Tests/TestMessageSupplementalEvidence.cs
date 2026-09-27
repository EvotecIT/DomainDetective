namespace DomainDetective.Tests;

public class TestMessageSupplementalEvidence {
    [Fact]
    public void DifferentSpfIdentitiesDoNotProduceAFalseConflict() {
        var message = new MessageHeaderAnalysis();
        message.Parse("Authentication-Results: mx.example; spf=pass smtp.mailfrom=one.example; spf=fail smtp.mailfrom=two.example\r\n",
            new MessageHeaderAnalysisOptions { TrustedAuthServIds = new[] { "mx.example" } });
        Assert.False(message.AuthenticationConflict);
        message.Parse("Authentication-Results: mx.example; spf=pass smtp.mailfrom=one.example; spf=fail smtp.mailfrom=one.example\r\n",
            new MessageHeaderAnalysisOptions { TrustedAuthServIds = new[] { "mx.example" } });
        Assert.True(message.AuthenticationConflict);
    }

    [Fact]
    public void DuplicateDkimTagsAreFlaggedAndMissingIdentityIsNotMisalignment() {
        var message = new MessageHeaderAnalysis();
        message.Parse("From: sender@example.com\r\nAuthentication-Results: mx.example; dkim=pass\r\nDKIM-Signature: v=1; d=example.com; d=other.example; s=one; a=rsa-sha256; h=from; b=YWJj; bh=YWJj\r\n");
        Assert.Null(message.DkimAlignment);
        Assert.Contains(message.Findings, value => value.Code == "HEADERS.DKIM.DuplicateTag");
        Assert.Equal("example.com", Assert.Single(message.DkimSignatures).Domain);
    }

    [Fact]
    public void EximTlsCipherIsRetained() {
        var hop = ReceivedHop.Parse("from sender.example by mx.example with esmtps X=TLS1.2:ECDHE-RSA-AES256-GCM-SHA384; Tue, 1 Sep 2026 12:00:00 +0000");
        Assert.Equal("TLS 1.2", hop.TlsVersion);
        Assert.Equal("ECDHE-RSA-AES256-GCM-SHA384", hop.TlsCipher);
    }
    [Fact]
    public void ReceivedSpfFallbackKeepsItsOwnWriterAndIdentity() {
        var message = new MessageHeaderAnalysis();
        message.Parse("From: sender@example.com\r\nAuthentication-Results: mx.example; dkim=pass header.d=example.com\r\nReceived-SPF: pass (comment; fail); receiver=other.example; envelope-from=sender@example.com; client-ip=192.0.2.10\r\n");
        Assert.Equal("pass", message.SpfResult);
        Assert.Equal("Strict", message.SpfAlignment);
        Assert.Equal("other.example", message.SpfEvidence!.AuthServId);
        Assert.Equal(MessageAuthenticationTrust.Unverified, message.SpfEvidence.Trust);
        Assert.Equal("mx.example", message.AuthServId);
        message.Parse(message.RawHeaders!, new MessageHeaderAnalysisOptions { TrustedAuthServIds = new[] { "mx.example" } });
        Assert.Null(message.SpfResult);
        Assert.Null(message.SpfEvidence);
        Assert.Equal(MessageAuthenticationTrust.Configured, message.AuthenticationTrust);
    }

    [Theory]
    [InlineData("130", "trusted ARC sealer")]
    [InlineData("108", "body modification")]
    [InlineData("9999", "Unknown")]
    public void CompositeAuthenticationMeaningPreservesEvidenceBoundary(string reason, string expected) {
        var message = new MessageHeaderAnalysis();
        message.Parse("Authentication-Results: compauth=pass reason=" + reason + "\r\n");
        Assert.Equal(reason, message.CompAuthReason);
        Assert.Contains(expected, message.CompAuthReasonMeaning!);
    }

    [Fact]
    public void MicrosoftVerdictMeaningsAndUnknownMechanismsArePreserved() {
        var message = new MessageHeaderAnalysis();
        message.Parse("X-Forefront-Antispam-Report: CAT:PHSH;SFV:SKN;IPV:CAL;UNKNOWN:opaque\r\nX-MS-Exchange-Organization-AuthMechanism: 999\r\n");
        Assert.Equal("Phishing", message.DefenderVerdictMeanings["CAT"]);
        Assert.Contains("bypass", message.DefenderVerdictMeanings["SFV"]);
        Assert.Equal("opaque", message.DefenderVerdicts["UNKNOWN"]);
        Assert.Contains("Unknown", message.ExchangeAuthMechanismMeaning!);
    }

    [Fact]
    public void ProviderHintsRequireWholeHostPatternMatch() {
        Assert.Contains("Microsoft 365", ReceivedHop.Parse("from sender.example by tenant.mail.protection.outlook.com with ESMTP").ProviderHints);
        Assert.Empty(ReceivedHop.Parse("from sender.example by tenant.mail.protection.outlook.com.attacker.example with ESMTP").ProviderHints);
    }
}

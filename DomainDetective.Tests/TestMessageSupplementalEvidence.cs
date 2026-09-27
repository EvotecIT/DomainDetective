namespace DomainDetective.Tests;

public class TestMessageSupplementalEvidence {
    [Theory]
    [InlineData("Authentication-Results: mx.example; spf=pass smtp.mailfrom=<> smtp.helo=example.com", "Strict")]
    [InlineData("Authentication-Results: mx.example; spf=pass smtp.mailfrom=\"\" smtp.helo=mail.example.com", "Relaxed")]
    [InlineData("Received-SPF: pass; receiver=mx.example; envelope-from=<>; helo=example.com", "Strict")]
    [InlineData("Authentication-Results: mx.example; spf=pass smtp.mailfrom=other.example smtp.helo=example.com", "None")]
    [InlineData("Authentication-Results: mx.example; spf=pass smtp.helo=example.com", null)]
    public void SpfHeloFallbackRequiresANullReversePath(string evidence, string? alignment) {
        var message = new MessageHeaderAnalysis();
        message.Parse("From: sender@example.com\r\n" + evidence + "\r\n");
        Assert.Equal(alignment, message.SpfAlignment);
    }

    [Theory]
    [InlineData("192.168.1.2", true)]
    [InlineData("172.16.0.1", true)]
    [InlineData("10.0.0.1", true)]
    [InlineData("127.0.0.1", true)]
    [InlineData("169.254.1.1", true)]
    [InlineData("100.64.0.1", true)]
    [InlineData("8.8.8.8", false)]
    public void MappedIpv4UsesTheSamePrivateClassification(string address, bool privateIp) {
        var mapped = ReceivedHop.Parse("from sender.example [IPv6:::ffff:" + address + "] by mx.example with ESMTP");
        var ipv4 = ReceivedHop.Parse("from sender.example [" + address + "] by mx.example with ESMTP");
        Assert.Equal(privateIp, ipv4.IsPrivateIp);
        Assert.Equal(ipv4.IsPrivateIp, mapped.IsPrivateIp);
        Assert.NotNull(mapped.FromIp);
    }

    [Theory]
    [InlineData(null, false)]
    [InlineData("<mailto:leave@example.com>", false)]
    [InlineData("<http://example.com/leave>", false)]
    [InlineData("<https://example.com/leave>", true)]
    [InlineData("< https://example.com/\r\n leave >", true)]
    [InlineData("<mailto:leave@example.com>, <https://example.com/leave>", true)]
    [InlineData("(comment <https://invalid.example>) <https://example.com/leave(a,b)>", true)]
    [InlineData("(comment <https://example.com/leave>)", false)]
    [InlineData("<https://example.com/one>, <https://example.com/two>", false)]
    public void OneClickAdvertisementRequiresOneHttpsEndpoint(string? targets, bool advertised) {
        var message = new MessageHeaderAnalysis();
        message.Parse("List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n" + (targets == null ? "" : "List-Unsubscribe: " + targets + "\r\n"));
        Assert.Equal(advertised, message.ListUnsubscribeOneClick);
    }

    [Fact]
    public void DuplicateUnsubscribeFieldsCannotAdvertiseAnUnambiguousOneClickTarget() {
        var message = new MessageHeaderAnalysis();
        message.Parse("List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\nList-Unsubscribe: <https://example.com/one>\r\nList-Unsubscribe: <https://example.com/two>\r\n");
        Assert.False(message.ListUnsubscribeOneClick);
    }

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

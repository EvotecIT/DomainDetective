using System.Text;

namespace DomainDetective.Tests;

public class TestMessageParserSafeguards {
    [Fact]
    public void ReuseWithEmptyInputClearsEveryMessageResult() {
        var analysis = new MessageHeaderAnalysis();
        analysis.Parse("From: sender@example.com\r\nReply-To: someone@other.example\r\nList-Id: Example <list.example.com>\r\nX-MS-Exchange-Organization-AuthMechanism: 10\r\nX-Spam-Status: Yes, score=6.3 tests=ONE,TWO\r\nDKIM-Signature: d=example.com; s=s1; b=YWJj; h=from\r\n");
        analysis.SignatureVerification.Add(new MessageSignatureVerification { Method = "DKIM", Status = MessageSignatureStatus.Valid });
        Assert.NotEmpty(analysis.Findings);
        analysis.Parse(string.Empty);
        Assert.Empty(analysis.Fields);
        Assert.Empty(analysis.Findings);
        Assert.Empty(analysis.DkimSignatures);
        Assert.Empty(analysis.SignatureVerification);
        Assert.Empty(analysis.FromAddresses);
        Assert.Empty(analysis.ReplyToAddresses);
        Assert.Empty(analysis.ExchangeHeaders);
        Assert.Null(analysis.ListId);
        Assert.Null(analysis.SpamAssassinScore);
        Assert.Null(analysis.ExchangeAuthMechanism);
        Assert.Null(analysis.SpfAlignment);
        Assert.Equal(MessageAuthenticationTrust.None, analysis.AuthenticationTrust);
    }

    [Theory]
    [InlineData("from sender.example [IPv6:2001:db8::1] by receiver.example with ESMTPSA (version=TLS1_2 cipher=TLS_ECDHE_RSA); Tue, 24 Oct 2023 12:34:56 +0000", "2001:db8::1", "TLS 1.2", "TlsAuthenticated")]
    [InlineData("from sender.example (rdns.example [192.168.1.2]) by receiver.example (using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384) with ESMTP; Tue, 24 Oct 2023 12:34:56 +0000", "192.168.1.2", "TLS 1.3", "Tls")]
    [InlineData("from sender.example by receiver.example with ESMTP; Tue, 24 Oct 2023 12:34:56 +0000", null, null, "Plain")]
    public void HopDetailsRetainReportedTransport(string raw, string? ip, string? tls, string protocol) {
        var hop = ReceivedHop.Parse(raw);
        Assert.Equal("sender.example", hop.FromHost);
        Assert.Equal("receiver.example", hop.ByHost);
        Assert.Equal(ip, hop.FromIp);
        Assert.Equal(tls, hop.TlsVersion);
        Assert.Equal(protocol, hop.ProtocolClass);
        Assert.NotNull(hop.Timestamp);
    }

    [Fact]
    public void MissingHostAndCommentKeywordsDoNotBecomeRouteClauses() {
        var hop = ReceivedHop.Parse("from sender.example (by forged.example; with ESMTPS) by (comment) with ESMTP; Tue, 24 Oct 2023 12:34:56 +0000");
        Assert.Equal("sender.example", hop.FromHost);
        Assert.Null(hop.ByHost);
        Assert.Equal("Plain", hop.ProtocolClass);
        Assert.NotNull(hop.Timestamp);
    }

    [Fact]
    public void LargeSignatureDoesNotUseUnboundedStackMemory() {
        var analysis = new MessageHeaderAnalysis();
        analysis.Parse("DKIM-Signature: d=example.com; s=s1; b=" + new string('A', 300000) + "; h=from\r\n");
        Assert.Single(analysis.DkimSignatures);
    }

    [Fact]
    public async Task FullMessageHeaderLimitIsEnforcedBeforeVerification() {
        using var health = new DomainHealthCheck();
        await Assert.ThrowsAsync<ArgumentException>(() => health.AnalyzeMessageAsync(Encoding.UTF8.GetBytes("Subject: " + new string('a', 1000) + "\r\n\r\nBody"), new MessageVerificationOptions { HeaderOptions = new MessageHeaderAnalysisOptions { MaximumHeaderCharacters = 100 } }));
    }
}

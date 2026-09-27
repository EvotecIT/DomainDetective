using System.Text;
using DomainDetective.Reports;

namespace DomainDetective.Tests;

public class TestMessageCompletionBoundaries {
    [Theory]
    [InlineData("by user")]
    [InlineData("with ESMTPS")]
    [InlineData("from user")]
    [InlineData("id user")]
    [InlineData("via user")]
    [InlineData("for user")]
    [InlineData("quoted \\\" by user")]
    public void QuotedRecipientTextDoesNotBecomeRouteClauses(string localPart) {
        var hop = ReceivedHop.Parse("from sender.example by receiver.example with ESMTP id actual for <\"" + localPart + "\"@example.org>; Tue, 24 Oct 2023 12:34:56 +0000");
        Assert.Equal("sender.example", hop.FromHost);
        Assert.Equal("receiver.example", hop.ByHost);
        Assert.Equal("ESMTP", hop.With);
        Assert.Equal("actual", hop.Id);
        Assert.Null(hop.Via);
        Assert.Equal("<\"" + localPart + "\"@example.org>", hop.For);
    }

    [Fact]
    public void QuotedRecipientTransportTokensAreNotConnectionEvidence() {
        var hop = ReceivedHop.Parse("from sender.example by receiver.example with ESMTP for <\"TLSv1.3 cipher=FAKE\"@example.org>");
        Assert.Null(hop.TlsVersion);
        Assert.Null(hop.TlsCipher);
        Assert.Equal("Plain", hop.ProtocolClass);
    }

    [Fact]
    public async Task ExpectedMxFindingsSurviveLoggerlessFullMessageComparison() {
        var raw = "From: sender@example.org\r\nX-MS-Exchange-Organization-AuthAs: Anonymous\r\nX-Forefront-Antispam-Report: CIP:203.0.113.20;H:sender.example.org\r\nReceived: from sender.example.org by tenant.mail.protection.outlook.com with ESMTP; Tue, 24 Oct 2023 12:34:56 +0000\r\n\r\nbody";
        using var health = new DomainHealthCheck();
        var message = await health.AnalyzeMessageAsync(Encoding.UTF8.GetBytes(raw));
        message.CompareExpectedMx(new[] { "expected.example.org" });
        Assert.True(message.ExpectedMxBypassed);
        Assert.Contains(message.Assessments, a => a.Code == "HEADERS.Route.ExpectedMxBypassed");
        Assert.Contains(MessageHeaderReport.Build(message).Single(s => s.Title == "Findings").Rows, row => row[1] == "HEADERS.Route.ExpectedMxBypassed");
        message.CompareExpectedMx(new[] { "sender.example.org" });
        Assert.False(message.ExpectedMxBypassed);
        Assert.DoesNotContain(message.Assessments, a => a.Code == "HEADERS.Route.ExpectedMxBypassed");
    }

    [Fact]
    public async Task MimeLoadDeadlineReturnsInconclusiveInsteadOfCallerCancellation() {
        var bytes = Encoding.UTF8.GetBytes("From: sender@example.org\r\nSubject: parse deadline\r\nContent-Type: text/plain\r\n\r\n" + new string('a', 8 * 1024 * 1024));
        using var health = new DomainHealthCheck();
        var result = await health.AnalyzeMessageAsync(bytes, new MessageVerificationOptions { Timeout = TimeSpan.FromTicks(1) });
        Assert.Contains(result.SignatureVerification, v => v.Status == MessageSignatureStatus.Inconclusive && v.Explanation.Contains("MIME", StringComparison.Ordinal));
    }
}

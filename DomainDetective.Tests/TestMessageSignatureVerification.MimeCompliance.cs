using System.Text;
using MimeKit;

namespace DomainDetective.Tests;

public partial class TestMessageSignatureVerification {
    [Fact]
    public async Task MimeComplianceRetainsByteLocationsAndCapsAllFindings() {
        var text = "From: sender@example.com\r\nTo: recipient@example.net\r\n" +
            string.Concat(Enumerable.Range(0, 10).Select(index => $"X-Test-{index}: value\0end\r\n")) +
            "\r\nSynthetic body\r\n";
        var bytes = Encoding.UTF8.GetBytes(text);
        using var health = new DomainHealthCheck();
        var analysis = await health.AnalyzeMessageAsync(bytes, new MessageVerificationOptions { MaximumMimeComplianceIssues = 2 });

        Assert.Equal(2, analysis.MimeComplianceIssues.Count);
        Assert.True(analysis.MimeComplianceTruncated);
        var first = analysis.MimeComplianceIssues[0];
        Assert.Equal(Array.IndexOf(bytes, (byte)0), first.StreamOffset);
        Assert.True(first.LineNumber > 0);
        Assert.True(first.ColumnNumber > 0);
        Assert.Contains(analysis.Assessments, finding => finding.Code == "MIME.Compliance.Truncated");
        Assert.Equal(3, analysis.Assessments.Count(finding => finding.Code?.StartsWith("MIME.", StringComparison.Ordinal) == true));
    }

    [Fact]
    public async Task SingleHeaderLimitReportsIncompleteVerificationWithoutLosingHeaderEvidence() {
        var text = "From: sender@example.com\r\nSubject: " + new string('x', 200) + "\r\n\r\nSynthetic body\r\n";
        using var health = new DomainHealthCheck();
        var analysis = await health.AnalyzeMessageAsync(Encoding.UTF8.GetBytes(text),
            new MessageVerificationOptions { MaximumMimeHeaderBytes = 128 });

        Assert.Equal("sender@example.com", Assert.Single(analysis.FromAddresses).Address);
        Assert.Equal(MessageSignatureStatus.Inconclusive, Assert.Single(analysis.SignatureVerification).Status);
        Assert.False(analysis.OriginalMessageInspectedForSignatures);
    }
}

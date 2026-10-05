using System.IO;
using System.Text;

namespace DomainDetective.Tests;

public class TestMessageFileInput {
    [Theory]
    [InlineData("\r\n")]
    [InlineData("\n")]
    public async Task EmptyBodyFileDoesNotClaimBodyEvidence(string newline) {
        var path = Path.GetTempFileName();
        try {
            File.WriteAllText(path, "From: sender@example.com" + newline + newline);
            using var health = new DomainHealthCheck();
            var result = await health.AnalyzeMessageFileAsync(path);
            Assert.False(result.HadBody);
        } finally { File.Delete(path); }
    }

    [Theory]
    [InlineData("\r\n")]
    [InlineData("\n")]
    public async Task HeaderOnlyFileReadStopsBeforeLargeBody(string newline) {
        var path = Path.GetTempFileName();
        try {
            File.WriteAllText(path, "From: sender@example.com" + newline + "Subject: Bounded input" + newline + newline + new string('a', 100000));
            using var health = new DomainHealthCheck();
            var result = await health.AnalyzeMessageFileAsync(path, options: new MessageVerificationOptions { HeaderOptions = new MessageHeaderAnalysisOptions { MaximumHeaderCharacters = 100 }, MaximumMessageBytes = 100 });
            Assert.Equal("Bounded input", result.Subject);
            Assert.True(result.HadBody);
            Assert.Equal(path, result.Source);
            Assert.DoesNotContain(new string('a', 100), result.RawHeaders!);
            await Assert.ThrowsAsync<ArgumentException>(() => health.AnalyzeMessageFileAsync(path, verifySignatures: true, options: new MessageVerificationOptions { MaximumMessageBytes = 100 }));
        } finally { File.Delete(path); }
    }

    [Fact]
    public async Task CanceledInputDoesNotYieldPartialAnalysis() {
        using var health = new DomainHealthCheck();
        using var canceled = new CancellationTokenSource();
        canceled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => health.AnalyzeMessageAsync(Encoding.UTF8.GetBytes("From: sender@example.com\r\n\r\nbody"), cancellationToken: canceled.Token));
        Assert.ThrowsAny<OperationCanceledException>(() => health.AnalyzeMessageHeaders("From: sender@example.com", cancellationToken: canceled.Token));
    }
}

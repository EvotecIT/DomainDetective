namespace DomainDetective.Tests;

public class TestMailTlsRunReset {
    [Theory]
    [InlineData("hosts", true)]
    [InlineData("hosts", false)]
    [InlineData("endpoints", true)]
    [InlineData("endpoints", false)]
    [InlineData("starttls", true)]
    [InlineData("starttls", false)]
    public async Task CanceledPreflightCannotExposeThePreviousScan(string input, bool alreadyCanceled) {
        using var caller = new CancellationTokenSource();
        if (alreadyCanceled) { caller.Cancel(); }
        IEnumerable<string> Hosts() {
            yield return "one.example.test";
            caller.Cancel();
            yield return "two.example.test";
        }
        if (input == "starttls") {
            var analysis = new STARTTLSAnalysis();
            analysis.ServerResults["previous.example.test:25"] = true;
            analysis.DowngradeDetected["previous.example.test:25"] = false;
            analysis.ServerDetails["previous.example.test:25"] = new();
            analysis.Assessments.Add(new Assessment { Code = "Synthetic.Previous", Severity = AssessmentSeverity.Warning });
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => analysis.AnalyzeServers(Hosts(), new[] { 25 }, new InternalLogger(), caller.Token));
            Assert.Empty(analysis.ServerResults);
            Assert.Empty(analysis.DowngradeDetected);
            Assert.Empty(analysis.ServerDetails);
            Assert.Empty(analysis.Assessments);
        } else {
            var analysis = new MailTlsAnalysis();
            analysis.ServerResults["previous.example.test:143"] = new MailTlsAnalysis.TlsResult { GradeLevel = GradeLevel.B };
            analysis.Assessments.Add(new Assessment { Code = "Synthetic.Previous", Severity = AssessmentSeverity.Warning });
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => input == "hosts"
                ? analysis.AnalyzeServers(MailTlsAnalysis.MailProtocol.Imap, Hosts(), 143, new InternalLogger(), caller.Token)
                : analysis.AnalyzeServers(MailTlsAnalysis.MailProtocol.Imap, Hosts().Select(host => new MailTransportEndpoint(host, 143)), new InternalLogger(), caller.Token));
            Assert.Empty(analysis.ServerResults);
            Assert.Empty(analysis.Assessments);
        }
    }
}

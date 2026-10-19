namespace DomainDetective.Tests;

public class TestMailTlsRunReset {
    [Theory]
    [InlineData("imap", true)]
    [InlineData("imap", false)]
    [InlineData("pop3", true)]
    [InlineData("pop3", false)]
    [InlineData("smtp", true)]
    [InlineData("smtp", false)]
    [InlineData("starttls", true)]
    [InlineData("starttls", false)]
    public async Task DomainPreflightFailureClearsPriorMailEvidence(string protocol, bool canceled) {
        using var health = new DomainHealthCheck();
        using var caller = new CancellationTokenSource();
        if (canceled) { caller.Cancel(); }
        health.DnsConfiguration.QueryDnsResponseOverride = (_, _, _) => throw new FormatException("Synthetic discovery failure.");
        if (protocol == "starttls") {
            var analysis = health.StartTlsAnalysis;
            analysis.Subject = "previous.example.test";
            analysis.ServerResults["previous.example.test:25"] = true;
            analysis.DowngradeDetected["previous.example.test:25"] = false;
            analysis.ServerDetails["previous.example.test:25"] = new();
            analysis.Assessments.Add(new Assessment { Code = "Synthetic.Previous" });
            var run = health.VerifySTARTTLS("second.example.test", cancellationToken: caller.Token);
            if (canceled) { await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run); }
            else { await Assert.ThrowsAsync<FormatException>(() => run); }
            Assert.Empty(analysis.ServerResults);
            Assert.Empty(analysis.DowngradeDetected);
            Assert.Empty(analysis.ServerDetails);
            Assert.Empty(analysis.Assessments);
            Assert.Equal("second.example.test", analysis.Subject);
        } else {
            MailTlsAnalysis analysis = protocol == "imap" ? health.ImapTlsAnalysis : protocol == "pop3" ? health.Pop3TlsAnalysis : health.SmtpTlsAnalysis;
            analysis.Subject = "previous.example.test";
            analysis.ServerResults["previous.example.test:25"] = new();
            analysis.Assessments.Add(new Assessment { Code = "Synthetic.Previous" });
            var run = protocol == "imap" ? health.VerifyIMAPTLS("second.example.test", caller.Token) :
                protocol == "pop3" ? health.VerifyPOP3TLS("second.example.test", caller.Token) : health.VerifySMTPTLS("second.example.test", caller.Token);
            if (canceled) { await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run); }
            else { await Assert.ThrowsAsync<FormatException>(() => run); }
            Assert.Empty(analysis.ServerResults);
            Assert.Empty(analysis.Assessments);
            Assert.Equal("second.example.test", analysis.Subject);
        }
    }

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

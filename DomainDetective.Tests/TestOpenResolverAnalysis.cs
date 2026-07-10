namespace DomainDetective.Tests;

public class TestOpenResolverAnalysis {
    [Fact]
    public async Task DetectsRecursionAllowed() {
        var analysis = new OpenResolverAnalysis { RecursionTestOverride = (_, _) => Task.FromResult(true) };
        var port = PortHelper.GetFreePort();
        await analysis.AnalyzeServer("server", port, new InternalLogger());
        Assert.True(analysis.ServerResults[$"server:{port}"]);
        Assert.Equal(OpenResolverStatus.Open, analysis.ServerDetails[$"server:{port}"].Status);
        PortHelper.ReleasePort(port);
    }

    [Fact]
    public async Task DetectsRecursionDisabled() {
        var analysis = new OpenResolverAnalysis { RecursionTestOverride = (_, _) => Task.FromResult(false) };
        var port = PortHelper.GetFreePort();
        await analysis.AnalyzeServer("server", port, new InternalLogger());
        Assert.False(analysis.ServerResults[$"server:{port}"]);
        Assert.Equal(OpenResolverStatus.Closed, analysis.ServerDetails[$"server:{port}"].Status);
        PortHelper.ReleasePort(port);
    }

    [Fact]
    public async Task ResultsResetBetweenRuns() {
        var analysis = new OpenResolverAnalysis { RecursionTestOverride = (_, _) => Task.FromResult(true) };
        var portA = PortHelper.GetFreePort();
        await analysis.AnalyzeServer("a", portA, new InternalLogger());
        var portB = PortHelper.GetFreePort();
        await analysis.AnalyzeServer("b", portB, new InternalLogger());
        Assert.False(analysis.ServerResults.ContainsKey($"a:{portA}"));
        Assert.True(analysis.ServerResults[$"b:{portB}"]);
        PortHelper.ReleasePort(portA);
        PortHelper.ReleasePort(portB);
    }

    [Fact]
    public async Task FailedProbeIsNotReportedAsClosed() {
        var analysis = new OpenResolverAnalysis {
            RecursionDetailOverride = (host, port, _) => Task.FromResult(new OpenResolverResult {
                Host = host,
                Port = port,
                Status = OpenResolverStatus.Failed,
                Error = "timeout"
            })
        };

        await analysis.AnalyzeServer("server", 53, new InternalLogger());

        Assert.False(analysis.ServerResults["server:53"]);
        Assert.Equal(OpenResolverStatus.Failed, analysis.ServerDetails["server:53"].Status);
        Assert.Contains(analysis.Assessments, a => a.Code == OpenResolverCodes.CheckFailed);
        Assert.DoesNotContain(analysis.Assessments, a => a.Code == OpenResolverCodes.RecursionClosed);
    }

    [Fact]
    public void MatchingRecursiveAnswerIsOpen() {
        var response = BuildResponse(0x1234, flags: 0x8180, answerCount: 1);
        var result = OpenResolverAnalysis.ParseResponse("resolver", 53, 0x1234, response);

        Assert.Equal(OpenResolverStatus.Open, result.Status);
        Assert.True(result.TransactionIdMatches);
        Assert.True(result.QuestionMatches);
    }

    [Fact]
    public void MismatchedTransactionIdIsFailed() {
        var response = BuildResponse(0x5678, flags: 0x8180, answerCount: 1);
        var result = OpenResolverAnalysis.ParseResponse("resolver", 53, 0x1234, response);

        Assert.Equal(OpenResolverStatus.Failed, result.Status);
        Assert.False(result.TransactionIdMatches);
    }

    [Fact]
    public void RefusedMatchingResponseIsClosed() {
        var response = BuildResponse(0x1234, flags: 0x8185, answerCount: 0);
        var result = OpenResolverAnalysis.ParseResponse("resolver", 53, 0x1234, response);

        Assert.Equal(OpenResolverStatus.Closed, result.Status);
    }

    [Fact]
    public void RecursiveResponseWithoutAnswerIsInconclusive() {
        var response = BuildResponse(0x1234, flags: 0x8180, answerCount: 0);
        var result = OpenResolverAnalysis.ParseResponse("resolver", 53, 0x1234, response);

        Assert.Equal(OpenResolverStatus.Failed, result.Status);
    }

    private static byte[] BuildResponse(ushort id, ushort flags, ushort answerCount) {
        var question = new byte[] {
            7, (byte)'e', (byte)'x', (byte)'a', (byte)'m', (byte)'p', (byte)'l', (byte)'e',
            3, (byte)'c', (byte)'o', (byte)'m', 0,
            0, 1, 0, 1
        };
        var response = new byte[12 + question.Length];
        response[0] = (byte)(id >> 8);
        response[1] = (byte)id;
        response[2] = (byte)(flags >> 8);
        response[3] = (byte)flags;
        response[5] = 1;
        response[6] = (byte)(answerCount >> 8);
        response[7] = (byte)answerCount;
        Buffer.BlockCopy(question, 0, response, 12, question.Length);
        return response;
    }
}

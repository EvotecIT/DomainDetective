namespace DomainDetective.Tests;

public class TestCliExitCodes {
    [Fact]
    public async Task InvalidSmimeFileReturnsErrorCode() {
        var code = await DomainDetective.CLI.Program.Main(new[] { "check", "--smime", "nonexistent.pem" });
        Assert.NotEqual(0, code);
    }
}

namespace DomainDetective.Tests {
    public class TestCLI {
        [Fact]
        public async Task CliRunsNsCheck() {
            var exitCode = await DomainDetective.CLI.Program.Run(new[] { "ns", "example.com" });
            Assert.Equal(0, exitCode);
        }
    }
}

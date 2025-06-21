namespace DomainDetective.Tests {
    public class TestWhoisAnalysis {
        [Fact]
        public async Task UnsupportedTldThrows() {
            var whois = new WhoisAnalysis();
            await Assert.ThrowsAsync<UnsupportedTldException>(async () => await whois.QueryWhoisServer("example.unknown"));
        }
    }
}

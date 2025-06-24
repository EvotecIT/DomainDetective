namespace DomainDetective.Tests {
    public class TestDkimGuess {
        [Fact]
        public async Task GuessSelectorsForDomain() {
            var healthCheck = new DomainHealthCheck { Verbose = false };
            await healthCheck.Verify("evotec.pl", new[] { HealthCheckType.DKIM });

            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults.ContainsKey("selector1"));
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults.ContainsKey("selector2"));
        }
    }
}
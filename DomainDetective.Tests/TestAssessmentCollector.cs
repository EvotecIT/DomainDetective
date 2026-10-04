namespace DomainDetective.Tests;

public class TestAssessmentCollector {
    [Fact]
    public void NestedScopesRetainUnchangedAssessmentContext() {
        var logger = new InternalLogger();
        var analysis = new DANEAnalysis();
        using var collector = AssessmentCollector.ForAnalysis(logger, analysis,
            category: "DANE", target: "example.com", source: "service lookup");

        using (collector.PushTarget("_443._tcp.example.com")) {
            using (collector.PushScope(source: "certificate probe")) {
                logger.WriteInformationCode("DANE.Certificate", "Certificate checked.");
            }
            logger.WriteInformationCode("DANE.Record", "TLSA record checked.");
        }
        logger.WriteInformationCode("DANE.Service", "Service checked.");

        Assert.Collection(analysis.Assessments,
            certificate => {
                Assert.Equal("DANE", certificate.Category);
                Assert.Equal("_443._tcp.example.com", certificate.Target);
                Assert.Equal("certificate probe", certificate.Source);
            },
            record => {
                Assert.Equal("DANE", record.Category);
                Assert.Equal("_443._tcp.example.com", record.Target);
                Assert.Equal("service lookup", record.Source);
            },
            service => {
                Assert.Equal("DANE", service.Category);
                Assert.Equal("example.com", service.Target);
                Assert.Equal("service lookup", service.Source);
            });
    }
}

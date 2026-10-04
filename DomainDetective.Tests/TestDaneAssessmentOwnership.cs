using DnsClientX;

namespace DomainDetective.Tests;

public class TestDaneAssessmentOwnership {
    [Theory]
    [InlineData("ports")]
    [InlineData("services")]
    [InlineData("service-type")]
    public async Task CertificateValidationIsRecordedOnceForItsTlsaOwner(string route) {
        const string owner = "_443._tcp.example.com";
        using var check = CreateCheck();
        check.DaneCertificateEvidenceOverride = (_, _, _) => Task.FromResult<DaneCertificateEvidence?>(new DaneCertificateEvidence {
            DnssecValidated = true
        });

        await Verify(check, route);

        var record = Assert.Single(check.DaneAnalysis.Assessments,
            item => item.Code == DaneCodes.RecordValid);
        Assert.Equal("DANE", record.Category);
        Assert.Equal(owner, record.Target);
        var assessment = Assert.Single(check.DaneAnalysis.Assessments,
            item => item.Code == DaneCodes.CertificateCheckFailed);
        Assert.Equal("DANE", assessment.Category);
        Assert.Equal(owner, assessment.Target);
    }

    [Fact]
    public async Task CertificateEvidenceFailureRemainsVisibleAfterDiscovery() {
        const string owner = "_443._tcp.example.com";
        using var check = CreateCheck();
        check.DaneCertificateEvidenceOverride = (_, _, _) => throw new InvalidOperationException("Evidence unavailable.");

        await check.VerifyDANE("example.com", new[] { 443 });

        var assessment = Assert.Single(check.DaneAnalysis.Assessments,
            item => item.Code == DaneCodes.CertificateCheckFailed);
        Assert.Equal("DANE", assessment.Category);
        Assert.Equal(owner, assessment.Target);
    }

    private static DomainHealthCheck CreateCheck() {
        var check = new DomainHealthCheck();
        check.DaneDnsOverride = (name, type) => Task.FromResult(type == DnsRecordType.TLSA
            ? new[] { new DnsAnswer {
                Name = name,
                Type = type,
                DataRaw = "3 1 1 " + new string('0', 64)
            } }
            : Array.Empty<DnsAnswer>());
        return check;
    }

    private static Task Verify(DomainHealthCheck check, string route) => route switch {
        "ports" => check.VerifyDANE("example.com", new[] { 443 }),
        "services" => check.VerifyDANE(new[] { new ServiceDefinition("example.com", 443) }),
        _ => check.VerifyDANE("example.com", new[] { ServiceType.HTTPS })
    };
}

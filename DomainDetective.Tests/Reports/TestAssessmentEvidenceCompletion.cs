using DnsClientX;
using DomainDetective.Reports;
using DomainDetective.Reports.Html;
using DomainDetective.Views;

namespace DomainDetective.Tests.Reports;

public class TestAssessmentEvidenceCompletion {
    private static string Render(params object[] views) {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".html");
        try {
            AssessmentHtmlReport.Generate(path, views);
            return File.ReadAllText(path);
        } finally { if (File.Exists(path)) { File.Delete(path); } }
    }

    [Fact]
    public void NestedInventoryRecordsSurviveAssessmentJsonAndHtml() {
        var query = new DnsInventoryQuery { RecordType = DnsRecordType.TXT, Status = DnsInventoryQueryStatus.Success };
        query.Records.Add(new DnsInventoryRecord { Name = "inventory.example.test", Type = DnsRecordType.TXT, Ttl = 3600, Data = "captured-inventory-value" });
        var view = new DnsInventoryInfo { Check = HealthCheckType.DNSINVENTORY, Subject = "example.test", Queries = new[] { query } };
        var json = DomainAssessmentJson.Serialize(DomainAssessmentBuilder.Build(new object[] { view }));
        Assert.Contains("captured-inventory-value", json);
        Assert.Contains("captured-inventory-value", Render(view));
    }

    [Theory]
    [InlineData(HealthCheckType.MX)]
    [InlineData(HealthCheckType.DNSSEC)]
    public void IncompleteInformationalEvidenceDoesNotEarnAPassingScore(HealthCheckType kind) {
        var informational = new[] { new Assessment { Severity = AssessmentSeverity.Info, Code = kind == HealthCheckType.MX ? "MX.Comparison.Incomplete" : "DNSSEC.Analysis.Incomplete", Message = "The requested comparison did not complete." } };
        object view = kind == HealthCheckType.MX
            ? new MxInfo { Check = kind, Subject = "example.test", Status = "Incomplete", Assessments = informational }
            : new DnssecStatusInfo { Check = kind, Subject = "example.test", ValidationStatus = DnssecValidationStatus.Indeterminate, Assessments = informational };
        var domain = Assert.Single(DomainAssessmentBuilder.Build(new[] { view }).Domains);
        var check = Assert.Single(domain.Checks);
        Assert.NotEqual(CheckOutcome.Pass, check.Outcome);
        Assert.NotEqual(100, check.Score);
        Assert.Equal(0, domain.PassedChecks);
    }

    [Fact]
    public void IndeterminateDnssecDoesNotClaimValidationInTheProfile() {
        var view = new DnssecStatusInfo { Check = HealthCheckType.DNSSEC, Subject = "example.test", ValidationStatus = DnssecValidationStatus.Indeterminate };
        Assert.DoesNotContain("DNSSEC is valid", Render(view));
    }

    [Theory]
    [InlineData(HealthCheckType.MX)]
    [InlineData(HealthCheckType.DNSBL)]
    public void AnIncompleteOnlyAreaDoesNotDisplayAPassingLabel(HealthCheckType kind) {
        object view = kind == HealthCheckType.MX
            ? new MxInfo { Check = kind, Subject = "example.test", Status = "Incomplete" }
            : new DnsblInfo { Check = kind, Subject = "example.test", Status = "Incomplete" };
        var html = Render(view);
        Assert.DoesNotContain(">Passing<", html);
        Assert.DoesNotContain("Every check passed.", html);
        Assert.Contains("Incomplete", html);
    }

    [Fact]
    public async Task DmarcProfileUsesTheEffectiveTestModePolicy() {
        using var health = new DomainHealthCheck();
        health.DmarcAnalysis.Subject = "example.test";
        await health.CheckDMARC("v=DMARC1; p=reject; t=y");
        var view = Converters.Convert(health.DmarcAnalysis);
        Assert.Equal("quarantine", view.EffectivePolicy);
        var check = Assert.Single(Assert.Single(DomainAssessmentBuilder.Build(new object[] { view }).Domains).Checks);
        Assert.Equal("quarantine", Assert.Single(check.Metrics, metric => metric.Label == "Policy").Value);
        Assert.DoesNotContain("spoofed mail is rejected", Render(view));
    }

    [Fact]
    public async Task FailedAndDeniedCaaDoNotClaimUnrestrictedIssuance() {
        var failure = new CheckFailureInfo(HealthCheckType.CAA, new Assessment { Severity = AssessmentSeverity.Error, Category = "CAA", Target = "example.test", Code = "Verification.Check.Failed", Message = "CAA unavailable." });
        Assert.DoesNotContain("no CAA record: anyone", Render(failure));
        using var health = new DomainHealthCheck();
        health.CAAAnalysis.Subject = "example.test";
        await health.CheckCAA("0 issue \";\"");
        var denied = Converters.Convert(health.CAAAnalysis);
        Assert.Equal(1, denied.ValidRecords);
        Assert.Empty(denied.CanIssueCertificatesForDomain);
        Assert.DoesNotContain("no CAA record: anyone", Render(denied));
    }

    [Fact]
    public void WildcardCaaDoesNotProduceAnUnprovenRenewalFailure() {
        var caa = new CaaInfo { Check = HealthCheckType.CAA, Subject = "example.test", ValidRecords = 2,
            CanIssueCertificatesForDomain = new[] { "other-ca.example.test" }, CanIssueWildcardCertificatesForDomain = new[] { "letsencrypt.org" } };
        var cert = new CertificateInfo { Check = HealthCheckType.CERT, Subject = "example.test", CertificateIssuer = "O=Let's Encrypt", SubjectAlternativeNames = new[] { "*.example.test" } };
        Assert.DoesNotContain("renewal will fail", Render(caa, cert));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void IncompleteAndFailedDnsblDoNotClaimCleanCoverage(bool failed) {
        object view = failed
            ? new CheckFailureInfo(HealthCheckType.DNSBL, new Assessment { Severity = AssessmentSeverity.Error, Category = "DNSBL", Target = "example.test", Code = "Verification.Check.Failed", Message = "Provider unavailable." })
            : new DnsblInfo { Check = HealthCheckType.DNSBL, Subject = "example.test", Status = "Incomplete" };
        Assert.DoesNotContain("Clean", Render(view));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task GeneralHtmlGeneratorPreservesTheRequestedTitleAndFindingVisibility(bool showInfo) {
        using var health = new DomainHealthCheck();
        health.DnsConfiguration.QueryDnsOverride = (_, _) => Task.FromResult(Array.Empty<DnsAnswer>());
        await health.Verify("example.test", new[] { HealthCheckType.CAA });
        health.CAAAnalysis.Assessments.Add(new Assessment { Severity = AssessmentSeverity.Info, Code = "CAA.Fixture.Note", Category = "CAA", Target = "example.test", Message = "custom-informational-proof" });
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".html");
        try {
            var result = await new HtmlReportGenerator().GenerateAsync(health, new ReportOptions { Format = ReportFormat.Html, Title = "Requested assessment title", OutputPath = path, ShowInfoFindings = showInfo });
            Assert.True(result.Success, result.ErrorMessage);
            Assert.Contains("Requested assessment title", File.ReadAllText(path));
            Assert.Equal(showInfo, File.ReadAllText(path).Contains("custom-informational-proof"));
        } finally { if (File.Exists(path)) { File.Delete(path); } }
    }

    [Fact]
    public void NestedPropagationResultsRetainTheirServerAndRecordEvidence() {
        var view = new DnsPropagationSetInfo { Check = HealthCheckType.DNSPROPAGATION, Subject = "example.test", Items = new[] {
            new DnsPropagationInfo { RecordType = DnsRecordType.TXT, Results = new[] {
                new DnsPropagationResultInfo { ServerName = "resolver.example.test", RecordType = DnsRecordType.TXT, Records = new[] { "captured-propagation-record" }, Success = true }
            } }
        } };
        var json = DomainAssessmentJson.Serialize(DomainAssessmentBuilder.Build(new object[] { view }));
        Assert.Contains("resolver.example.test", json);
        Assert.Contains("captured-propagation-record", json);
        Assert.Contains("captured-propagation-record", Render(view));
    }

    [Fact]
    public void DmarcSiblingReportingUsesTheDiscoveredOrganizationalBoundary() {
        var view = new DmarcRecordInfo { Subject = "mail.example.test", Check = HealthCheckType.DMARC,
            DmarcRecordExists = true, Policy = "reject", EffectivePolicy = "reject", OrganizationalDomain = "example.test",
            MailtoRua = new[] { "mailto:reports@reports.example.test" } };
        var check = Assert.Single(Assert.Single(DomainAssessmentBuilder.Build(new object[] { view }).Domains).Checks);
        var destinations = Assert.Single(check.Evidence, block => block.Title == "Report destinations");
        Assert.Equal("Not needed", Assert.Single(destinations.Rows)[2]);
    }

    [Fact]
    public async Task GeneralHtmlGeneratorRetainsCompletedSupplementalEvidence() {
        using var health = new DomainHealthCheck();
        health.DnsConfiguration.QueryDnsOverride = (_, _) => Task.FromResult(Array.Empty<DnsAnswer>());
        health.PlainHttpAnalysis.HttpHandlerFactory = () => new HttpStubMessageHandler((_, _) => throw new System.Net.Http.HttpRequestException("supplemental-http-proof"));
        await health.Verify("example.test", new[] { HealthCheckType.SPF }, executionOptions: new HealthCheckExecutionOptions { IncludePlainHttp = true });
        Assert.True(health.VerificationPlainHttpCompleted);
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".html");
        try {
            var result = await new HtmlReportGenerator().GenerateAsync(health, new ReportOptions { Format = ReportFormat.Html, OutputPath = path });
            Assert.True(result.Success, result.ErrorMessage);
            Assert.Contains("supplemental-http-proof", File.ReadAllText(path));
        } finally { if (File.Exists(path)) { File.Delete(path); } }
    }
}

using System.IO.Compression;
using DomainDetective.Reports;
using DomainDetective.Reports.Html;
using DomainDetective.Reports.Office;
using DomainDetective.Views;
using Wording = DomainDetective.Reports.AssessmentReportWording;

namespace DomainDetective.Tests.Reports;

public partial class TestAssessmentExports {
    private static CaaInfo NoCaa(string domain) => new() { Check = HealthCheckType.CAA, Subject = domain, ValidRecords = 0, InvalidRecords = 0 };

    [Fact]
    public void ADomainWithoutCaaIsNeitherAPassNorAFailureAndClaimsNoRestriction() {
        CheckAssessment check = Assert.Single(Assert.Single(DomainAssessmentBuilder.Build(new object[] { NoCaa("example.test") }).Domains).Checks);

        Assert.Equal(CheckOutcome.Info, check.Outcome);
        Assert.False(check.Scored);
        Assert.True(Wording.IsNoCaaPolicy(check));
        Assert.Equal("No CAA policy", Wording.ControlValue(check));
        Assert.Equal("Any certificate authority may issue certificates.", Wording.ControlReason(check));

        var withPolicy = new CaaInfo { Check = HealthCheckType.CAA, Subject = "example.test", ValidRecords = 1, CanIssueCertificatesForDomain = new[] { "letsencrypt.org" } };
        CheckAssessment restricted = Assert.Single(Assert.Single(DomainAssessmentBuilder.Build(new object[] { withPolicy }).Domains).Checks);
        Assert.False(Wording.IsNoCaaPolicy(restricted));
        Assert.True(restricted.Scored);
    }

    [Fact]
    public void EveryFormatAgreesThatNoCaaPolicyMeansAnyCaMayIssue() {
        InDirectory(directory => {
            DomainAssessmentReport single = DomainAssessmentBuilder.Build(new object[] { NoCaa("example.test") });
            var html = new AngleSharp.Html.Parser.HtmlParser().ParseDocument(AssessmentHtmlReport.Render(single));
            var control = html.QuerySelectorAll(".dd-control").Single(c => c.QuerySelector(".dd-control-name")?.TextContent == "CAA");
            Assert.Equal("No CAA policy", control.QuerySelector(".dd-control-value")!.TextContent);
            Assert.DoesNotContain("Only the listed CAs", html.DocumentElement.TextContent);

            DomainAssessmentReport several = DomainAssessmentBuilder.Build(new object[] { NoCaa("one.test"), NoCaa("two.test") });
            var multi = new AngleSharp.Html.Parser.HtmlParser().ParseDocument(AssessmentHtmlReport.Render(several));
            var multiControl = multi.QuerySelectorAll(".dd-control").Single(c => c.QuerySelector(".dd-control-name")?.TextContent == "CAA");
            Assert.Equal("No CAA policy", multiControl.QuerySelector(".dd-control-value")!.TextContent);

            string wordPath = Path.Combine(directory, "caa.docx"), excelPath = Path.Combine(directory, "caa.xlsx");
            AssessmentWordReport.Generate(wordPath, several);
            AssessmentExcelReport.Generate(excelPath, several);
            using var word = ZipFile.OpenRead(wordPath);
            string document = Load(word, "word/document.xml").Root!.Value;
            Assert.Contains("No CAA policy", document);
            Assert.DoesNotContain("Only the listed CAs", document);
            using var excel = ZipFile.OpenRead(excelPath);
            string workbook = WorkbookText(excel);
            Assert.Contains("any certificate authority may issue", workbook);
            Assert.DoesNotContain("Only the listed CAs", workbook);
        });
    }
}

public class TestAssessmentAbsentAndObserved {
    [Fact]
    public void AMissingTlsRptRecordIsNotAPassThatClaimsReporting() {
        var view = new TlsRptInfo { Check = HealthCheckType.TLSRPT, Subject = "example.test", TlsRptRecordExists = false, Assessments = System.Array.Empty<Assessment>() };
        CheckAssessment check = Assert.Single(Assert.Single(DomainAssessmentBuilder.Build(new object[] { view }).Domains).Checks);

        Assert.Equal(CheckOutcome.Info, check.Outcome);
        Assert.False(check.Scored);
        Assert.Equal("Not published", Wording.ControlValue(check));
        Assert.Equal("Mail TLS failures are not reported.", Wording.ControlReason(check));
    }

    [Fact]
    public void AnObservedTlsFailureIsADefectNotACheckThatCouldNotRun() {
        var view = new MxInfo { Check = HealthCheckType.MX, Subject = "example.test", Assessments = new[] {
            new Assessment { Severity = AssessmentSeverity.Warning, Code = "WEBAVAILABILITY.Public.TlsFailed",
                Message = "Public web endpoint request failed: The SSL connection could not be established." }
        } };
        CheckAssessment check = Assert.Single(Assert.Single(DomainAssessmentBuilder.Build(new object[] { view }).Domains).Checks);

        Assert.True(check.EvidenceComplete);
        Assert.Equal(CheckOutcome.Warning, check.Outcome);
    }

    [Fact]
    public void ACheckWithErrorsStaysInTheScoreWhenOneLookupDidNotFinish() {
        var view = new MxInfo { Check = HealthCheckType.MX, Subject = "example.test", Assessments = new[] {
            new Assessment { Severity = AssessmentSeverity.Error, Code = "MX.Fixture.Error", Message = "Mail server name is a CNAME." },
            new Assessment { Severity = AssessmentSeverity.Warning, Code = "MX.Address.QueryFailed", Message = "Address query failed for mx2.example.test." }
        } };
        DomainAssessment domain = Assert.Single(DomainAssessmentBuilder.Build(new object[] { view }).Domains);
        CheckAssessment check = Assert.Single(domain.Checks);

        Assert.False(check.EvidenceComplete);
        Assert.Equal(CheckOutcome.Error, check.Outcome);
        Assert.NotNull(check.Score);
        Assert.Equal(check.Score, domain.Score);
        Assert.True(domain.Coverage < 1);
    }
}

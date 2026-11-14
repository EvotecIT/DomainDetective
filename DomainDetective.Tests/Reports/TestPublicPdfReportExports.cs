using System.Reflection;
using DomainDetective.Reports;
using DomainDetective.Reports.Office;
using DomainDetective.Views;
using OfficeIMO.Word;

namespace DomainDetective.Tests.Reports;

public class TestPublicPdfReportExports {
    [Fact]
    public void PaperBatchBuildsOneDocumentForWordAndPdf() {
        InDirectory(directory => {
            int builds = 0;
            var outputs = new Dictionary<ReportFormat, string> {
                [ReportFormat.Word] = Path.Combine(directory, "report.docx"),
                [ReportFormat.Pdf] = Path.Combine(directory, "report.pdf")
            };
            // This is the real production factory boundary, not a test-only hook or a renderer mock.
            var batch = typeof(AssessmentWordReport).Assembly.GetType("DomainDetective.Reports.Office.WordReportExport", true)!;
            var generate = batch.GetMethod("Generate", BindingFlags.Static | BindingFlags.NonPublic)!;
            Func<WordDocument> build = () => { builds++; return AssessmentWordReport.Build(AssessmentExportFixture.Create()); };
            var results = Assert.IsAssignableFrom<IReadOnlyList<ReportResult>>(generate.Invoke(null, new object?[] { outputs, build, null, CancellationToken.None }));
            Assert.Equal(1, builds);
            Assert.Equal(2, results.Count);
            Assert.All(results, result => {
                Assert.True(result.Success, result.ErrorMessage);
                Assert.True(result.FileSize > 1000);
                Assert.Contains("example.test", ReportArtifactText.Read(result.FilePath));
            });
        });
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PublicBatchExportsPdfWithOtherFormats(bool pdfFirst) {
        string directory = Path.Combine(Path.GetTempPath(), "dd-public-pdf-" + Guid.NewGuid().ToString("N"));
        try {
            ReportFormat[] formats = pdfFirst ? new[] { ReportFormat.Pdf, ReportFormat.Html, ReportFormat.Word }
                : new[] { ReportFormat.Html, ReportFormat.Word, ReportFormat.Pdf };
            var result = await CompositionExportService.ExportAsync(new CompositionExportRequest {
                Items = new object[] { new SpfRecordInfo {
                    Subject = "example.test", Check = HealthCheckType.SPF,
                    Assessments = new[] { new Assessment { Severity = AssessmentSeverity.Warning, Code = "PDF.FIXTURE", Message = "Published PDF fixture finding" } }
                } },
                Formats = formats, ExportPath = Path.Combine(directory, "assessment.html"), AutoCollectTtl = false
            });
            Assert.Equal(formats, result.Reports.Select(report => report.Format));
            Assert.All(result.Reports, report => {
                Assert.True(report.Success, report.ErrorMessage);
                Assert.True(report.FileSize > 0);
                string text = ReportArtifactText.Read(report.FilePath);
                Assert.Contains("example.test", text);
                Assert.Contains("Published PDF fixture finding", text);
            });
            Assert.Equal(new[] { "assessment.docx", "assessment.html", "assessment.pdf" },
                Directory.GetFiles(directory).Select(Path.GetFileName).OrderBy(name => name, StringComparer.Ordinal));
        } finally { if (Directory.Exists(directory)) { Directory.Delete(directory, true); } }
    }

    [Fact]
    public void PaperBatchRetainsPdfWhenWordDestinationFails() {
        InDirectory(directory => {
            string blocked = Path.Combine(directory, "blocked.docx");
            Directory.CreateDirectory(blocked);
            string pdf = Path.Combine(directory, "report.pdf");
            var results = AssessmentWordReport.GenerateReports(new Dictionary<ReportFormat, string> {
                [ReportFormat.Word] = blocked, [ReportFormat.Pdf] = pdf
            }, AssessmentExportFixture.Create());
            Assert.False(results.Single(result => result.Format == ReportFormat.Word).Success);
            Assert.True(results.Single(result => result.Format == ReportFormat.Pdf).Success);
            Assert.Contains("example.test", ReportArtifactText.Read(pdf));
        });
    }

    [Fact]
    public void PaperBatchStopsAfterCancelledBuildBeforeWritingEitherFormat() {
        InDirectory(directory => {
            using var cancellation = new CancellationTokenSource();
            Func<WordDocument> build = () => {
                WordDocument document = AssessmentWordReport.Build(AssessmentExportFixture.Create());
                cancellation.Cancel();
                return document;
            };
            var outputs = new Dictionary<ReportFormat, string> {
                [ReportFormat.Word] = Path.Combine(directory, "cancelled.docx"),
                [ReportFormat.Pdf] = Path.Combine(directory, "cancelled.pdf")
            };
            var batch = typeof(AssessmentWordReport).Assembly.GetType("DomainDetective.Reports.Office.WordReportExport", true)!;
            var generate = batch.GetMethod("Generate", BindingFlags.Static | BindingFlags.NonPublic)!;
            var error = Assert.Throws<TargetInvocationException>(() => generate.Invoke(null,
                new object?[] { outputs, build, null, cancellation.Token }));
            Assert.IsAssignableFrom<OperationCanceledException>(error.InnerException);
            Assert.Empty(Directory.GetFiles(directory));
        });
    }

    [Fact]
    public void PdfConversionObservesCancellationDuringLayout() {
        InDirectory(directory => {
            using var cancellation = new CancellationTokenSource();
            int callbacks = 0;
            var report = AssessmentExportFixture.Create();
            report.Domains[0].Checks[0].Findings[0].Message = new string('x', 512);
            var options = new AssessmentWordOptions {
                PdfOptions = new OfficeIMO.Word.Pdf.WordToPdfOptions {
                    PdfOptions = new OfficeIMO.Pdf.PdfOptions {
                        TextLineBreakCallback = _ => {
                            callbacks++;
                            cancellation.Cancel();
                            return Array.Empty<int>();
                        }
                    }
                }
            };
            string pdf = Path.Combine(directory, "cancelled.pdf");
            Assert.ThrowsAny<OperationCanceledException>(() => AssessmentWordReport.GenerateReports(
                new Dictionary<ReportFormat, string> { [ReportFormat.Pdf] = pdf }, report, options, cancellation.Token));
            Assert.True(callbacks > 0, "Cancellation must occur inside real PDF layout, after the Word document is built.");
            Assert.False(File.Exists(pdf));
        });
    }

    private static void InDirectory(Action<string> action) {
        string directory = Path.Combine(Path.GetTempPath(), "dd-paper-pdf-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try { action(directory); } finally { Directory.Delete(directory, true); }
    }
}

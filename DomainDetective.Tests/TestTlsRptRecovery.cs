using DomainDetective.Reports;
using DomainDetective.Reports.Office;
using DomainDetective.TimeSeries.TlsRpt;
using DomainDetective.Views;
using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Xml.Linq;
using Xunit;

namespace DomainDetective.Tests;

public class TestTlsRptRecovery {
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void PublicReimportSelectsCorrectedVersionAndPreservesLegacyBytes(bool oldTotalsWereContaminated) {
        string root = Path.Combine(Path.GetTempPath(), "dd-tlsrpt-recovery-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try {
            var store = new TlsRptTimeSeriesStore(Path.Combine(root, "store"));
            var old = new TlsRptSnapshot { Domain = "example.com", ReportId = "reimport-1", ReporterOrgName = "Sender",
                RangeBeginUtc = DateTimeOffset.Parse("2026-01-01T00:00:00Z"), RangeEndUtc = DateTimeOffset.Parse("2026-01-02T00:00:00Z"),
                TotalSuccessfulSessions = 10, TotalFailedSessions = oldTotalsWereContaminated ? 105 : 5,
                IngestedAtUtc = DateTimeOffset.UtcNow.AddHours(-1) };
            old.MxHosts.Add(new TlsRptMxSnapshot { MxHost = "*.example.com", SuccessfulSessions = 10, FailedSessions = old.TotalFailedSessions });
            string oldPath = store.SaveSnapshot(old);
            byte[] oldBytes = File.ReadAllBytes(oldPath);
            string input = Path.Combine(root, "report.json");
            File.WriteAllText(input, Report);
            var imported = TlsRptIngestion.IngestFromPath("example.com", input, store);
            Assert.Empty(imported.Errors);
            var active = Assert.Single(store.LoadSnapshots("example.com"));
            Assert.True(active.MxFailureAttributionVerified);
            Assert.Equal(10, active.TotalSuccessfulSessions);
            Assert.Equal(5, active.TotalFailedSessions);
            Assert.Equal(3, Assert.Single(active.MxHosts, h => h.MxHost == "mx.actual.example").FailedSessions);
            Assert.Equal(oldBytes, File.ReadAllBytes(oldPath));
            var info = Converters.Convert(store.LoadSnapshots("example.com"));
            Assert.Equal(10, info.TotalSuccessfulSessions);
            Assert.Equal(5, info.TotalFailedSessions);
            TlsRptIngestion.IngestFromPath("example.com", input, store);
            Assert.Single(store.LoadSnapshots("example.com"));
        } finally { Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public void DirectConversionPrefersCorrectedEvidenceAndKeepsUnidentifiedReports() {
        using var source = new MemoryStream(Encoding.UTF8.GetBytes(Report));
        var corrected = TlsRptSnapshotBuilder.Build(TlsRptReportParser.Parse(source), "example.com", "File", null);
        var old = new TlsRptSnapshot { Domain = "EXAMPLE.COM.", ReportId = corrected.ReportId, ReporterOrgName = corrected.ReporterOrgName,
            RangeBeginUtc = corrected.RangeBeginUtc, RangeEndUtc = corrected.RangeEndUtc, TotalFailedSessions = 105,
            IngestedAtUtc = corrected.IngestedAtUtc.AddHours(1) };
        var anonymous = new TlsRptSnapshot { Domain = "example.com", TotalFailedSessions = 2 };
        var info = Converters.Convert(new[] { old, corrected, anonymous, anonymous });
        Assert.Equal(3, info.SnapshotCount);
        Assert.Equal(10, info.TotalSuccessfulSessions);
        Assert.Equal(9, info.TotalFailedSessions);
        Assert.Contains(corrected, info.Snapshots);
        Assert.DoesNotContain(old, info.Snapshots);
    }

    [Fact]
    public void DetailedWordReportLeavesReceivingHostSuccessesUnattributed() {
        string root = Path.Combine(Path.GetTempPath(), "dd-tlsrpt-word-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try {
            using var source = new MemoryStream(Encoding.UTF8.GetBytes(Report));
            var snapshot = TlsRptSnapshotBuilder.Build(TlsRptReportParser.Parse(source), "example.com", "File", null);
            string path = Path.Combine(root, "report.docx");
            DomainDetective.Reports.Office.AssessmentWordReport.Generate(path, DomainAssessmentBuilder.Build(new object[] { Converters.Convert(new[] { snapshot }) }), new DomainDetective.Reports.Office.AssessmentWordOptions { ShowInfoFindings = true });
            using var zip = ZipFile.OpenRead(path);
            using var xml = zip.GetEntry("word/document.xml")!.Open();
            var document = XDocument.Load(xml);
            XNamespace w = "http://schemas.openxmlformats.org/wordprocessingml/2006/main";
            string CellText(XElement cell) => DomainDetective.Tests.Reports.ReportArtifactText.Normalize(cell.Value).Trim();
            var table = document.Descendants(w + "tbl").First(t => t.Descendants(w + "tc").Any(c => CellText(c) == "mx.actual.example"));
            var rows = table.Elements(w + "tr").Select(r => r.Elements(w + "tc").Select(CellText).ToArray()).ToArray();
            var headers = rows[0];
            int successColumn = Array.FindIndex(headers, label => label.Equals("Successful Sessions", StringComparison.OrdinalIgnoreCase));
            int failureColumn = Array.FindIndex(headers, label => label.Equals("Failed Sessions", StringComparison.OrdinalIgnoreCase));
            int domainColumn = Array.FindIndex(headers, label => label == "Domain");
            Assert.InRange(successColumn, 0, headers.Length - 1);
            Assert.InRange(failureColumn, 0, headers.Length - 1);
            Assert.InRange(domainColumn, 0, headers.Length - 1);
            var receivingHost = Assert.Single(rows.Skip(1), cells => cells.Contains("mx.actual.example"));
            Assert.Equal("example.com", receivingHost[domainColumn]);
            Assert.Equal("Not attributed", receivingHost[successColumn]);
            Assert.Equal("3", receivingHost[failureColumn]);
        } finally { Directory.Delete(root, recursive: true); }
    }

    private const string Report = "{\"organization-name\":\"Sender\",\"report-id\":\"reimport-1\",\"date-range\":{\"start-datetime\":\"2026-01-01T00:00:00Z\",\"end-datetime\":\"2026-01-02T00:00:00Z\"},\"policies\":[{\"policy\":{\"policy-type\":\"sts\",\"policy-domain\":\"example.com\",\"mx-host\":[\"*.example.com\"]},\"summary\":{\"total-successful-session-count\":10,\"total-failure-session-count\":5},\"failure-details\":[{\"result-type\":\"certificate-expired\",\"receiving-mx-hostname\":\"mx.actual.example\",\"failed-session-count\":3}]},{\"policy\":{\"policy-type\":\"sts\",\"policy-domain\":\"other.example\",\"mx-host\":[\"mx.other.example\"]},\"summary\":{\"total-successful-session-count\":0,\"total-failure-session-count\":100}}]}";
}

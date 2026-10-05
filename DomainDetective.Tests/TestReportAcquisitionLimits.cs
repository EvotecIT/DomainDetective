using DomainDetective.TimeSeries;
using DomainDetective.TimeSeries.TlsRpt;
using DomainDetective.TimeSeries.DmarcAggregate;
using System;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Linq;
using Xunit;

namespace DomainDetective.Tests;

public class TestReportAcquisitionLimits {
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void DefaultFileIngestionRejectsExpandedReportsAboveFiftyMiB(bool tlsRpt) {
        string root = Path.Combine(Path.GetTempPath(), "dd-report-limits-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try {
            string path = Path.Combine(root, "large.gz");
            using (var file = File.Create(path))
            using (var gzip = new GZipStream(file, CompressionMode.Compress)) {
                byte[] spaces = Encoding.ASCII.GetBytes(new string(' ', 8192));
                for (int i = 0; i < 50 * 1024 * 1024 / spaces.Length; i++) gzip.Write(spaces, 0, spaces.Length);
                byte[] report = Encoding.UTF8.GetBytes(tlsRpt
                    ? "{\"organization-name\":\"Sender\",\"report-id\":\"large\",\"date-range\":{\"start-datetime\":\"2026-01-01T00:00:00Z\",\"end-datetime\":\"2026-01-02T00:00:00Z\"},\"policies\":[]}"
                    : File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Reports", "rfc9990-example.xml")));
                gzip.Write(report, 0, report.Length);
            }
            var errors = tlsRpt
                ? TlsRptIngestion.IngestFromPath("example.com", path, new TlsRptTimeSeriesStore(Path.Combine(root, "store"))).Errors
                : DmarcAggregateIngestion.IngestFromPath(path, new DmarcAggregateTimeSeriesStore(Path.Combine(root, "store"))).Errors;
            Assert.True(errors.Any(error => error.Contains("max", StringComparison.OrdinalIgnoreCase) && error.Contains("size", StringComparison.OrdinalIgnoreCase)), string.Join("\n", errors));
            var unlimitedErrors = tlsRpt
                ? TlsRptIngestion.IngestFromPath("example.com", path, new TlsRptTimeSeriesStore(Path.Combine(root, "store")), true, 0).Errors
                : DmarcAggregateIngestion.IngestFromPath(path, new DmarcAggregateTimeSeriesStore(Path.Combine(root, "store")), true, 0).Errors;
            Assert.Empty(unlimitedErrors);
        } finally { Directory.Delete(root, true); }
    }
}

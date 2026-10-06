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
            WriteLargeReport(path, tlsRpt);
            if (tlsRpt) {
                Assert.Throws<IOException>(() => TlsRptJsonParser.ParseReport(path));
                Assert.NotEmpty(TlsRptJsonParser.ParseReport(path, 0));
            } else {
                Assert.Throws<IOException>(() => DmarcReportParser.Parse(path));
                Assert.NotEmpty(DmarcReportParser.Parse(path, null, 0).Records);
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

#if NET10_0_OR_GREATER || NET472
    [Theory]
    [InlineData("Import-DDDmarcReport")]
    [InlineData("Test-DDDmarcAggregate")]
    [InlineData("Import-DDEmailTlsRpt")]
    public void SummaryCommandsRetainAnExplicitExpansionLimitOverride(string command) {
        string root = Path.Combine(Path.GetTempPath(), "dd-summary-limits-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try {
            string path = Path.Combine(root, "large.gz");
            WriteLargeReport(path, command == "Import-DDEmailTlsRpt");
            var state = System.Management.Automation.Runspaces.InitialSessionState.CreateDefault2();
            Type cmdlet = command == "Import-DDDmarcReport" ? typeof(PowerShell.CmdletImportDmarcReport)
                : command == "Import-DDEmailTlsRpt" ? typeof(PowerShell.CmdletImportTlsRpt) : typeof(PowerShell.CmdletTestDmarcAggregate);
            state.Commands.Add(new System.Management.Automation.Runspaces.SessionStateCmdletEntry(command, cmdlet, null));
            using var runspace = System.Management.Automation.Runspaces.RunspaceFactory.CreateRunspace(state);
            runspace.Open();
            using (var limited = System.Management.Automation.PowerShell.Create()) {
                limited.Runspace = runspace;
                limited.AddCommand(command).AddParameter("Path", path);
                string failure = string.Empty;
                try { Assert.Empty(limited.Invoke()); }
                catch (System.Management.Automation.RuntimeException exception) { failure = exception.Message; }
                failure += string.Join("\n", limited.Streams.Error.Select(error => error.ToString()))
                    + string.Join("\n", limited.Streams.Warning.Select(warning => warning.Message));
                Assert.Contains("max", failure, StringComparison.OrdinalIgnoreCase);
                Assert.Contains("size", failure, StringComparison.OrdinalIgnoreCase);
            }
            using var unlimited = System.Management.Automation.PowerShell.Create();
            unlimited.Runspace = runspace;
            unlimited.AddCommand(command).AddParameter("Path", path).AddParameter("MaxUncompressedMb", 0);
            Assert.NotEmpty(unlimited.Invoke());
            Assert.Empty(unlimited.Streams.Error);
            Assert.Empty(unlimited.Streams.Warning);
        } finally { Directory.Delete(root, true); }
    }
#endif

    private static void WriteLargeReport(string path, bool tlsRpt) {
        using var file = File.Create(path);
        using var gzip = new GZipStream(file, CompressionMode.Compress);
        byte[] spaces = Encoding.ASCII.GetBytes(new string(' ', 8192));
        for (int i = 0; i < 50 * 1024 * 1024 / spaces.Length; i++) gzip.Write(spaces, 0, spaces.Length);
        byte[] report = Encoding.UTF8.GetBytes(tlsRpt
            ? File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Data", "tlsrpt.json"))
            : File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Reports", "rfc9990-example.xml")));
        gzip.Write(report, 0, report.Length);
    }
}

using System.Collections.Generic;
using DomainDetective.Reports.Html.Advanced;

namespace DomainDetective.Tests;

public class TestAdvancedReportBase {
    private class DummyReport : AdvancedReportBase {
        public DummyReport(DomainHealthCheck hc) : base(hc, "example.com") { }
        public IReadOnlyList<LogEventArgs> Logs => ProgressLog;
    }

    [Fact]
    public void AddsLogEntry() {
        var report = new DummyReport(new DomainHealthCheck());
        var entry = new LogEventArgs("Activity", "Step", 1, 2, 50);
        var method = report.GetType().GetMethod("AddProgressLog", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!;
        method.Invoke(report, new object[] { entry });
        Assert.Single(report.Logs);
        Assert.Equal("Step", report.Logs[0].ProgressCurrentOperation);
    }
}

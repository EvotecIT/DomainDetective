using DomainDetective.TimeSeries.TlsRpt;
using System;
using System.IO;
using System.Linq;
using System.Text;
using Xunit;

namespace DomainDetective.Tests;

public class TestTlsRptPolicyAttribution {
    [Fact]
    public void MixedReportStoresOnlyRequestedDomainPolicies() {
        string root = Path.Combine(Path.GetTempPath(), "dd-tlsrpt-scope-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try {
            string input = Path.Combine(root, "mixed.json");
            File.WriteAllText(input, Report(
                Policy("example.com", "\"mx.example.com\"", 10, 0) + "," +
                Policy("other.example", "\"mx.other.example\"", 0, 100)));
            var store = new TlsRptTimeSeriesStore(Path.Combine(root, "store"));
            var result = TlsRptIngestion.IngestFromPath("example.com", input, store);
            Assert.Empty(result.Errors);
            var saved = Assert.Single(store.LoadSnapshots("example.com"));
            Assert.Equal(10, saved.TotalSuccessfulSessions);
            Assert.Equal(0, saved.TotalFailedSessions);
            Assert.DoesNotContain(saved.MxHosts, mx => mx.MxHost == "mx.other.example");
        } finally { Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public void StandardMxPatternArrayKeepsOnePolicySummary() {
        using var input = new MemoryStream(Encoding.UTF8.GetBytes(Report(
            Policy("example.com", "[\"mx1.example.com\",\"*.example.com\"]", 10, 5))));
        var report = TlsRptReportParser.Parse(input);
        var policy = Assert.Single(report.Policies);
        Assert.Equal("mx1.example.com", policy.Policy.MxHost);
        Assert.Equal(new[] { "mx1.example.com", "*.example.com" }, policy.Policy.MxHostPatterns);
        var snapshot = TlsRptSnapshotBuilder.Build(report, "example.com", "File", null);
        Assert.Equal(10, snapshot.TotalSuccessfulSessions);
        Assert.Equal(5, snapshot.TotalFailedSessions);
    }

    [Fact]
    public void ReceivingHostFailuresAreNotAssignedToPolicyPatterns() {
        string details = ",\"failure-details\":[{\"result-type\":\"certificate-expired\",\"failed-session-count\":3,\"receiving-mx-hostname\":\"mx.actual.example\"}]";
        string policy = Policy("example.com", "\"*.example.com\"", 10, 5);
        policy = policy.Substring(0, policy.Length - 1) + details + "}";
        using var input = new MemoryStream(Encoding.UTF8.GetBytes(Report(policy)));
        var report = TlsRptReportParser.Parse(input);
        var snapshot = TlsRptSnapshotBuilder.Build(report, "example.com", "File", null);
        Assert.Equal(10, snapshot.TotalSuccessfulSessions);
        Assert.Equal(5, snapshot.TotalFailedSessions);
        Assert.DoesNotContain(snapshot.MxHosts, mx => mx.MxHost == "*.example.com");
        Assert.Equal(3, Assert.Single(snapshot.MxHosts, mx => mx.MxHost == "mx.actual.example").FailedSessions);
        Assert.Equal(2, Assert.Single(snapshot.MxHosts, mx => mx.MxHost == "(unknown)").FailedSessions);
    }

    [Fact]
    public void ExplicitDomainScopeNormalizesCaseAndTrailingDot() {
        using var input = new MemoryStream(Encoding.UTF8.GetBytes(Report(Policy("example.com.", "\"mx.example.com\"", 10, 0))));
        var report = TlsRptReportParser.Parse(input);
        var snapshot = TlsRptSnapshotBuilder.Build(report, "EXAMPLE.COM.", "File", null);
        Assert.Equal("example.com", snapshot.Domain);
        Assert.Equal(10, snapshot.TotalSuccessfulSessions);
    }

    [Fact]
    public void MixedReportCannotInferOneDomainOrIncludeUnscopedPolicies() {
        using var input = new MemoryStream(Encoding.UTF8.GetBytes(Report(
            Policy("example.com", "[\"mx.example.com\"]", 10, 0) + "," +
            Policy("other.example", "[\"mx.other.example\"]", 20, 1) + "," +
            Policy("", "[]", 1000, 1000))));
        var report = TlsRptReportParser.Parse(input);
        Assert.Throws<ArgumentException>(() => TlsRptSnapshotBuilder.Build(report, "", "File", null));
        var scoped = TlsRptSnapshotBuilder.Build(report, "example.com", "File", null);
        Assert.Equal(10, scoped.TotalSuccessfulSessions);
        Assert.Equal(0, scoped.TotalFailedSessions);
        Assert.NotEmpty(scoped.ValidationMessages);
        Assert.Empty(scoped.MxHosts);
    }

    [Fact]
    public void DanePolicyWithoutMxPatternsAndUnspecifiedDomainRemainExplicit() {
        string policy = Policy("example.com", "[]", 3, 0).Replace("\"policy-type\":\"sts\"", "\"policy-type\":\"tlsa\"").Replace("\"mx-host\":[],", "");
        using var input = new MemoryStream(Encoding.UTF8.GetBytes(Report(policy)));
        var report = TlsRptReportParser.Parse(input);
        Assert.Empty(Assert.Single(report.Policies).Policy.MxHostPatterns);
        var snapshot = TlsRptSnapshotBuilder.Build(report, "", "File", null);
        Assert.Equal("example.com", snapshot.Domain);
        Assert.Equal(3, snapshot.TotalSuccessfulSessions);
        Assert.Empty(snapshot.MxHosts);
    }

    [Fact]
    public void DetailTotalsDoNotRewriteAuthoritativePolicySummary() {
        var report = new TlsRptReport();
        var policy = new TlsRptPolicyResult { Policy = new TlsRptPolicy { PolicyDomain = "example.com", MxHost = "*.example.com" },
            Summary = new TlsRptPolicySummary { SuccessfulSessionCount = 10, FailedSessionCount = 2 } };
        policy.FailureDetails.Add(new TlsRptFailureDetail { ReceivingMxHostname = "MX.ACTUAL.EXAMPLE.", FailedSessionCount = 3, ResultType = "certificate-expired" });
        report.Policies.Add(policy);
        var snapshot = TlsRptSnapshotBuilder.Build(report, "example.com", "File", null);
        Assert.Equal(2, snapshot.TotalFailedSessions);
        Assert.NotEmpty(snapshot.ValidationMessages);
        var host = Assert.Single(snapshot.MxHosts);
        Assert.Equal("mx.actual.example", host.MxHost);
        Assert.Equal(3, host.FailedSessions);
        Assert.False(host.SuccessfulSessionsKnown);
        var info = DomainDetective.Views.Converters.Convert(new[] { snapshot });
        Assert.False(Assert.Single(info.MxHosts).SuccessfulSessionsKnown);
        Assert.Contains(info.Assessments, a => a.Code == "TLSRPT.Reports.Validation");
    }

    [Fact]
    public void LegacyStoredSnapshotKeepsTotalsWithoutPretendingMxAttribution() {
        string root = Path.Combine(Path.GetTempPath(), "dd-tlsrpt-legacy-" + Guid.NewGuid().ToString("N"));
        try {
            var store = new TlsRptTimeSeriesStore(root);
            store.SaveSnapshot(new TlsRptSnapshot { Domain = "example.com", ReportId = "old", TotalSuccessfulSessions = 10, TotalFailedSessions = 5,
                MxHosts = new System.Collections.Generic.List<TlsRptMxSnapshot> { new() { MxHost = "*.example.com", SuccessfulSessions = 10, FailedSessions = 5 } } });
            var loaded = store.LoadSnapshots("example.com");
            var info = DomainDetective.Views.Converters.Convert(loaded);
            Assert.Equal(10, info.TotalSuccessfulSessions);
            Assert.Equal(5, info.TotalFailedSessions);
            Assert.Empty(info.MxHosts);
            Assert.Contains(info.Assessments, a => a.Code == "TLSRPT.Reports.LegacyMxAttribution");
        } finally { if (Directory.Exists(root)) Directory.Delete(root, recursive: true); }
    }

    private static string Report(string policies) => "{\"organization-name\":\"Independent sender\",\"report-id\":\"mixed-1\","
        + "\"date-range\":{\"start-datetime\":\"2026-01-01T00:00:00Z\",\"end-datetime\":\"2026-01-02T00:00:00Z\"},\"policies\":[" + policies + "]}";
    private static string Policy(string domain, string mxJson, int ok, int failed) => "{\"policy\":{\"policy-type\":\"sts\",\"policy-domain\":\""
        + domain + "\",\"mx-host\":" + mxJson + ",\"policy-string\":[\"version: STSv1\",\"mode: enforce\"]},"
        + "\"summary\":{\"total-successful-session-count\":" + ok + ",\"total-failure-session-count\":" + failed + "}}";
}

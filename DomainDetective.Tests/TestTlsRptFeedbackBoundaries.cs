using DomainDetective.TimeSeries.TlsRpt;
using DomainDetective.Views;
using System;
using System.IO;
using Xunit;

namespace DomainDetective.Tests;

public class TestTlsRptFeedbackBoundaries {
    [Fact]
    public void CorrectedReceivingEvidenceGetsItsOwnImmutableVersion() {
        string root = Path.Combine(Path.GetTempPath(), "dd-tlsrpt-feedback-" + Guid.NewGuid().ToString("N"));
        try {
            var store = new TlsRptTimeSeriesStore(root);
            var old = Snapshot("mx.old.example", "expired");
            old.IngestedAtUtc = DateTimeOffset.UtcNow.AddHours(-1);
            string oldPath = store.SaveSnapshot(old);
            byte[] original = File.ReadAllBytes(oldPath);
            var corrected = Snapshot("mx.new.example", "untrusted");
            string correctedPath = store.SaveSnapshot(corrected);
            Assert.NotEqual(oldPath, correctedPath);
            Assert.Equal(original, File.ReadAllBytes(oldPath));
            var active = Assert.Single(store.LoadSnapshots("example.com"));
            Assert.Equal("mx.new.example", Assert.Single(active.MxHosts).MxHost);
            Assert.Contains("untrusted", active.FailureTypeCounts.Keys);
        } finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
    }

    [Fact]
    public void CorrectedReporterWhitespaceAndCaseDoNotDuplicateReportTotals() {
        var old = Snapshot("mx.old.example", "expired");
        old.ReporterOrgName = "Sender";
        old.IngestedAtUtc = DateTimeOffset.UtcNow.AddHours(-1);
        var newer = Snapshot("mx.new.example", "expired");
        newer.ReporterOrgName = " sender ";
        var info = Converters.Convert(new[] { old, newer });
        Assert.Equal(1, info.SnapshotCount);
        Assert.Equal(1, info.TotalFailedSessions);
    }

    [Fact]
    public void RecipientPolicyRetainsDaneForItsHostedMxAndExcludesUnrelatedPolicies() {
        var report = new TlsRptReport();
        report.Policies.Add(Policy("sts", "example.com", "mail.provider.test", 1));
        report.Policies.Add(Policy("tlsa", "mail.provider.test", "", 2));
        report.Policies.Add(Policy("tlsa", "unrelated.provider.test", "", 10));
        var snapshot = TlsRptSnapshotBuilder.Build(report, "example.com", "File", null);
        Assert.Equal(3, snapshot.TotalFailedSessions);
    }

    [Fact]
    public void OverlappingTypesDoNotInflateOneKnownFailedSession() {
        var report = new TlsRptReport();
        var policy = Policy("sts", "example.com", "mx.example.com", 1);
        policy.FailureDetails.Add(new TlsRptFailureDetail { ReceivingMxHostname = "mx.example.com", ResultType = "expired", FailedSessionCount = 1 });
        policy.FailureDetails.Add(new TlsRptFailureDetail { ReceivingMxHostname = "mx.example.com", ResultType = "untrusted", FailedSessionCount = 1 });
        report.Policies.Add(policy);
        var snapshot = TlsRptSnapshotBuilder.Build(report, "example.com", "File", null);
        Assert.Equal(1, snapshot.TotalFailedSessions);
        Assert.Equal(1, Assert.Single(snapshot.MxHosts).FailedSessions);
        Assert.Equal(1, snapshot.FailureTypeCounts["expired"]);
        Assert.Equal(1, snapshot.FailureTypeCounts["untrusted"]);
    }

    [Fact]
    public void AmbiguousFailureUnionRemainsUnattributedWhileTypesArePreserved() {
        var report = new TlsRptReport();
        var policy = Policy("sts", "example.com", "mx.example.com", 2);
        policy.FailureDetails.Add(new TlsRptFailureDetail { ReceivingMxHostname = "mx.example.com", ResultType = "expired", FailedSessionCount = 1 });
        policy.FailureDetails.Add(new TlsRptFailureDetail { ReceivingMxHostname = "mx.example.com", ResultType = "untrusted", FailedSessionCount = 1 });
        report.Policies.Add(policy);
        var snapshot = TlsRptSnapshotBuilder.Build(report, "example.com", "File", null);
        Assert.Equal(2, snapshot.TotalFailedSessions);
        var host = Assert.Single(snapshot.MxHosts);
        Assert.False(host.FailedSessionsKnown);
        Assert.Equal(0, host.FailedSessions);
        Assert.Equal(1, host.FailureByType["expired"]);
        Assert.Equal(1, host.FailureByType["untrusted"]);
        Assert.False(Assert.Single(Converters.Convert(new[] { snapshot }).MxHosts).FailedSessionsKnown);
        Assert.Contains(snapshot.ValidationMessages, message => message.Contains("Non-exclusive"));
    }

    [Theory]
    [InlineData("mail.provider.test", 3)]
    [InlineData("deep.mail.provider.test", 1)]
    public void MixedDaneAssociationUsesSingleLabelMxWildcards(string daneHost, int expected) {
        string root = Path.Combine(Path.GetTempPath(), "dd-tlsrpt-wildcard-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try {
            string file = Path.Combine(root, "report.json");
            File.WriteAllText(file, "{\"organization-name\":\"Sender\",\"report-id\":\"wildcard\",\"date-range\":{\"start-datetime\":\"2026-01-01T00:00:00Z\",\"end-datetime\":\"2026-01-02T00:00:00Z\"},\"policies\":[{\"policy\":{\"policy-type\":\"sts\",\"policy-domain\":\"example.com\",\"mx-host\":[\"*.provider.test\"]},\"summary\":{\"total-successful-session-count\":0,\"total-failure-session-count\":1}},{\"policy\":{\"policy-type\":\"tlsa\",\"policy-domain\":\"" + daneHost + "\"},\"summary\":{\"total-successful-session-count\":0,\"total-failure-session-count\":2}}]}");
            var result = TlsRptIngestion.IngestFromPath("example.com", file, new TlsRptTimeSeriesStore(Path.Combine(root, "store")));
            Assert.Empty(result.Errors);
            Assert.Equal(expected, Assert.Single(result.Snapshots).TotalFailedSessions);
        } finally { Directory.Delete(root, true); }
    }

    [Fact]
    public void SameHostAcrossAppliedPoliciesHasNoKnownDistinctSessionCount() {
        var report = new TlsRptReport();
        foreach (string type in new[] { "sts", "tlsa" }) {
            var policy = Policy(type, type == "sts" ? "example.com" : "mx.example.com", "mx.example.com", 1);
            policy.FailureDetails.Add(new TlsRptFailureDetail { ReceivingMxHostname = "mx.example.com", ResultType = "expired", FailedSessionCount = 1 });
            report.Policies.Add(policy);
        }
        var snapshot = TlsRptSnapshotBuilder.Build(report, "example.com", "File", null);
        Assert.Equal(2, snapshot.TotalFailedSessions); // Policy observations remain independently reported.
        Assert.False(Assert.Single(snapshot.MxHosts).FailedSessionsKnown);
        Assert.Equal(2, snapshot.FailureTypeCounts["expired"]);
    }

    [Fact]
    public void FolderIngestionKeepsBothCorrectedEvidenceVersionsAndDeduplicatesOnlyIdenticalEvidence() {
        string root = Path.Combine(Path.GetTempPath(), "dd-tlsrpt-batch-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try {
            string input = Path.Combine(root, "input"); Directory.CreateDirectory(input);
            string json = "{\"organization-name\":\"Sender\",\"report-id\":\"same\",\"date-range\":{\"start-datetime\":\"2026-01-01T00:00:00Z\",\"end-datetime\":\"2026-01-02T00:00:00Z\"},\"policies\":[{\"policy\":{\"policy-type\":\"sts\",\"policy-domain\":\"example.com\",\"mx-host\":[\"mx.example.com\"]},\"summary\":{\"total-successful-session-count\":0,\"total-failure-session-count\":1},\"failure-details\":[{\"result-type\":\"expired\",\"receiving-mx-hostname\":\"mx.old.example\",\"failed-session-count\":1}]}]}";
            File.WriteAllText(Path.Combine(input, "old.json"), json);
            File.WriteAllText(Path.Combine(input, "corrected.json"), json.Replace("mx.old.example", "mx.new.example"));
            File.WriteAllText(Path.Combine(input, "duplicate.json"), json);
            var store = new TlsRptTimeSeriesStore(Path.Combine(root, "store"));
            var result = TlsRptIngestion.IngestFromPath("example.com", input, store);
            Assert.Empty(result.Errors);
            Assert.Equal(2, result.Snapshots.Count);
            Assert.Equal(2, Directory.GetFiles(store.GetDomainDirectory("example.com")).Length);
            Assert.Single(store.LoadSnapshots("example.com"));
        } finally { Directory.Delete(root, true); }
    }

    private static TlsRptPolicyResult Policy(string type, string domain, string mx, int failed) => new() {
        Policy = new TlsRptPolicy { PolicyType = type, PolicyDomain = domain, MxHost = mx },
        Summary = new TlsRptPolicySummary { FailedSessionCount = failed }
    };
    private static TlsRptSnapshot Snapshot(string mx, string type) {
        var snapshot = new TlsRptSnapshot { Domain = "example.com", ReportId = "same-1", ReporterOrgName = "Sender",
            RangeBeginUtc = DateTimeOffset.Parse("2026-01-01T00:00:00Z"), RangeEndUtc = DateTimeOffset.Parse("2026-01-02T00:00:00Z"),
            TotalFailedSessions = 1, MxFailureAttributionVerified = true };
        var host = new TlsRptMxSnapshot { MxHost = mx, FailedSessions = 1 };
        host.FailureByType[type] = snapshot.FailureTypeCounts[type] = 1;
        snapshot.MxHosts.Add(host);
        return snapshot;
    }
}

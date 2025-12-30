using System;
using System.IO;
using System.Linq;
using DomainDetective.TimeSeries.TlsRpt;
using Xunit;

namespace DomainDetective.Tests {
    public class TestTlsRptIngestionDomainValidation {
        [Fact]
        public void IngestFromPath_RejectsTlsRptWhenPolicyDomainMismatches() {
            var root = CreateTempDirectory();
            try {
                var reportDir = Path.Combine(root, "reports");
                var storeDir = Path.Combine(root, "store");
                Directory.CreateDirectory(reportDir);
                Directory.CreateDirectory(storeDir);

                var json = BuildTlsRptJson(policyDomain: "other.example");
                File.WriteAllText(Path.Combine(reportDir, "tlsrpt.json"), json);

                var store = new TlsRptTimeSeriesStore(storeDir);
                var result = TlsRptIngestion.IngestFromPath("example.com", reportDir, store);

                Assert.Empty(result.Snapshots);
                Assert.Contains(result.Errors, e => e != null && e.IndexOf("policy-domain mismatch", StringComparison.OrdinalIgnoreCase) >= 0);
            } finally {
                TryDeleteDirectory(root);
            }
        }

        [Fact]
        public void IngestFromPath_AcceptsTlsRptWhenPolicyDomainMatches() {
            var root = CreateTempDirectory();
            try {
                var reportDir = Path.Combine(root, "reports");
                var storeDir = Path.Combine(root, "store");
                Directory.CreateDirectory(reportDir);
                Directory.CreateDirectory(storeDir);

                var json = BuildTlsRptJson(policyDomain: "example.com");
                File.WriteAllText(Path.Combine(reportDir, "tlsrpt.json"), json);

                var store = new TlsRptTimeSeriesStore(storeDir);
                var result = TlsRptIngestion.IngestFromPath("example.com", reportDir, store);

                Assert.Single(result.Snapshots);
                Assert.Equal("example.com", result.Snapshots[0].Domain);

                var stored = store.LoadSnapshots("example.com");
                Assert.Single(stored);
            } finally {
                TryDeleteDirectory(root);
            }
        }

        [Fact]
        public void IngestFromPath_AcceptsTlsRptWhenPolicyDomainMissing() {
            var root = CreateTempDirectory();
            try {
                var reportDir = Path.Combine(root, "reports");
                var storeDir = Path.Combine(root, "store");
                Directory.CreateDirectory(reportDir);
                Directory.CreateDirectory(storeDir);

                var json = BuildTlsRptJson(policyDomain: null);
                File.WriteAllText(Path.Combine(reportDir, "tlsrpt.json"), json);

                var store = new TlsRptTimeSeriesStore(storeDir);
                var result = TlsRptIngestion.IngestFromPath("example.com", reportDir, store);

                Assert.Single(result.Snapshots);
                Assert.Equal("example.com", result.Snapshots[0].Domain);
            } finally {
                TryDeleteDirectory(root);
            }
        }

        private static string BuildTlsRptJson(string? policyDomain) {
            var policyDomainJson = policyDomain == null ? string.Empty : $",\"policy-domain\":\"{policyDomain}\"";
            return "{"
                + "\"organization-name\":\"Test Org\","
                + "\"date-range\":{\"start-datetime\":\"2025-01-01T00:00:00Z\",\"end-datetime\":\"2025-01-02T00:00:00Z\"},"
                + "\"report-id\":\"r1\","
                + "\"policies\":["
                    + "{"
                        + "\"policy\":{"
                            + "\"policy-type\":\"sts\","
                            + "\"mx-host\":\"mx.example.com\""
                            + policyDomainJson + ","
                            + "\"policy-string\":[\"version: STSv1\",\"mode: enforce\"]"
                        + "},"
                        + "\"summary\":{"
                            + "\"total-successful-session-count\":1,"
                            + "\"total-failure-session-count\":0"
                        + "}"
                    + "}"
                + "]"
            + "}";
        }

        private static string CreateTempDirectory() {
            var root = Path.Combine(Path.GetTempPath(), "DomainDetectiveTests", Guid.NewGuid().ToString("n"));
            Directory.CreateDirectory(root);
            return root;
        }

        private static void TryDeleteDirectory(string path) {
            try {
                if (Directory.Exists(path)) {
                    Directory.Delete(path, recursive: true);
                }
            } catch {
                // ignore cleanup failures on CI/Windows
            }
        }
    }
}


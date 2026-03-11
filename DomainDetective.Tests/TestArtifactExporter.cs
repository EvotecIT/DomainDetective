using System;
using System.IO;
using System.Linq;
using DomainDetective;
using DomainDetective.Reports;
using DomainDetective.Reports.Artifacts;

namespace DomainDetective.Tests {
    public class TestArtifactExporter {
        [Fact]
        public void WritesCoreArtifacts()
        {
            // Arrange
            var hc = new DomainHealthCheck();
            // Seed a couple of assessments without network calls
            hc.DmarcAnalysis.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Message = "Test warning",
                Code = "TEST.WARNING",
                Category = "TEST",
                Target = "example.com",
                Timestamp = DateTimeOffset.UtcNow
            });
            hc.SpfAnalysis.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Message = "Test error",
                Code = "TEST.ERROR",
                Category = "TEST",
                Target = "example.com",
                Timestamp = DateTimeOffset.UtcNow
            });

            var tmp = Path.Combine(Path.GetTempPath(), "dd-artifacts-tests-" + Guid.NewGuid().ToString("n"));
            Directory.CreateDirectory(tmp);
            var exporter = new ArtifactExporter(tmp);
            var meta = new ArtifactMetadata { Subject = "example.com", GeneratedAt = DateTimeOffset.UtcNow, GeneratorVersion = "test" };
            var metrics = new ArtifactMetrics {
                AssessmentInfoCount = 0,
                AssessmentWarningCount = 1,
                AssessmentErrorCount = 1,
                RecommendationCount = hc.RecommendationViews.Count,
                HostCount = 0,
                ResourceCount = 0,
                TransferBytes = 0,
                TotalDurationSeconds = 0
            };

            // Act
            var dir = exporter.WriteAll("example.com", hc, meta, metrics);

            // Assert
            Assert.True(Directory.Exists(dir));
            var scanPath = Path.Combine(dir, "scan.json");
            var metricsPath = Path.Combine(dir, "metrics.json");
            Assert.True(File.Exists(scanPath));
            Assert.True(File.Exists(metricsPath));

            var scan = File.ReadAllText(scanPath);
            Assert.Contains("\"metadata\"", scan);
            Assert.Contains("TEST.WARNING", scan);
            Assert.Contains("TEST.ERROR", scan);
        }

        [Fact]
        public void ReportRunService_Can_Write_Artifacts_Without_Generating_A_Report()
        {
            var hc = new DomainHealthCheck();
            hc.DmarcAnalysis.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Message = "Artifact only warning",
                Code = "TEST.ARTIFACT",
                Category = "TEST",
                Target = "example.com",
                Timestamp = DateTimeOffset.UtcNow
            });

            var tmp = Path.Combine(Path.GetTempPath(), "dd-artifacts-only-" + Guid.NewGuid().ToString("n"));
            Directory.CreateDirectory(tmp);

            try
            {
                var logger = new InternalLogger(false);
                var runDirectory = ReportRunService.WriteArtifactsOnly(
                    logger,
                    "example.com",
                    hc,
                    exportPath: null,
                    defaultOutputDirectory: tmp);

                Assert.True(Directory.Exists(runDirectory));
                Assert.True(File.Exists(Path.Combine(runDirectory, "scan.json")));
                Assert.True(File.Exists(Path.Combine(runDirectory, "metrics.json")));
            }
            finally
            {
                if (Directory.Exists(tmp))
                {
                    Directory.Delete(tmp, recursive: true);
                }
            }
        }
    }
}

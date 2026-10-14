using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Reports;
using DomainDetective.Reports.Html;
using DomainDetective.Views;

namespace DomainDetective.Example;

/// <summary>
/// Example demonstrating how to generate the HTML assessment report and its JSON model.
/// </summary>
internal class ReportingHtmlExample {
    public static async Task Run() {
        Console.WriteLine("\n=== HTML Assessment Report Demo ===");
        Console.WriteLine("===================================\n");

        var reportsDir = "Reports";
        Directory.CreateDirectory(reportsDir);

        var domain = "github.com";
        Console.WriteLine($"Analyzing domain: {domain}");

        var healthCheck = new DomainHealthCheck();
        await healthCheck.Verify(domain);

        // Every check the run executed becomes a view; the assessment scores and groups them per domain.
        var items = Converters.ConvertChecks(healthCheck);
        DomainAssessmentReport assessment = DomainAssessmentBuilder.Build(items, new DomainAssessmentOptions { Title = $"Security Report — {domain}" });
        Console.WriteLine($"Score {assessment.Score} (grade {assessment.Grade}) across {assessment.Domains.Sum(static d => d.Checks.Count)} checks.");

        var htmlPath = Path.Combine(reportsDir, "DomainAssessment.html");
        AssessmentHtmlReport.Generate(htmlPath, assessment, new AssessmentHtmlOptions(), openInBrowser: true);
        Console.WriteLine($"   ✓ {htmlPath} created and opened in browser");

        var jsonPath = Path.Combine(reportsDir, "DomainAssessment.json");
        File.WriteAllText(jsonPath, DomainAssessmentJson.Serialize(assessment));
        Console.WriteLine($"   ✓ {jsonPath} created");

        await DemoBatchReporting();
    }

    public static async Task DemoBatchReporting() {
        Console.WriteLine("\n=== Multi-domain Assessment ===");

        var domains = new[] { "example.com", "google.com", "microsoft.com" };
        var reportsDir = "Reports/Batch";
        Directory.CreateDirectory(reportsDir);

        // One report for all domains: a summary, a coverage matrix across domains, and a section per domain.
        var items = new System.Collections.Generic.List<object>();
        foreach (var domain in domains) {
            try {
                Console.WriteLine($"Processing {domain}...");
                var healthCheck = new DomainHealthCheck();
                await healthCheck.Verify(domain);
                items.AddRange(Converters.ConvertChecks(healthCheck));
            }
            catch (Exception ex) {
                Console.WriteLine($"✗ Failed to analyze {domain}: {ex.Message}");
            }
        }

        var path = Path.Combine(reportsDir, "Assessment.html");
        AssessmentHtmlReport.Generate(path, items, new DomainAssessmentOptions { Title = "Domain assessment" });
        Console.WriteLine($"\nBatch report saved to '{path}'.");
    }
}

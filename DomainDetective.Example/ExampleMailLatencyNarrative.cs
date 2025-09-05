using System.Threading.Tasks;
using DomainDetective.Narratives;

namespace DomainDetective.Example;

public static partial class Program {
    /// <summary>
    /// Demonstrates building a narrative from mail latency analysis.
    /// </summary>
    public static async Task ExampleMailLatencyNarrative() {
        var health = new DomainHealthCheck();
        await health.CheckMailLatency("smtp.gmail.com");
        var sections = MailLatencyNarrative.Build(health.MailLatencyAnalysis);
        Helpers.ShowPropertiesTable("Mail Latency Narrative", sections);
    }
}

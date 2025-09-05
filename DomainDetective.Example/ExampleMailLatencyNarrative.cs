using System.Threading.Tasks;
using DomainDetective.Narratives;

namespace DomainDetective.Example;

public static partial class Program {
    /// <summary>
    /// Demonstrates building a mail latency narrative.
    /// </summary>
    public static async Task ExampleMailLatencyNarrative() {
        var analysis = new MailLatencyAnalysis();
        await analysis.AnalyzeServer("smtp.gmail.com", 25, new InternalLogger());
        var sections = MailLatencyNarrative.Build(analysis, analysis.Assessments);
        Helpers.ShowPropertiesTable("Mail Latency Narrative", sections);
    }
}

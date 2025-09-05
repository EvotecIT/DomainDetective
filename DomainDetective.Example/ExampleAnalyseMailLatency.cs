using System.Threading.Tasks;

namespace DomainDetective.Example;

public static partial class Program {
    /// <summary>
    /// Example analyzing mail latency for a server.
    /// </summary>
    public static async Task ExampleAnalyseMailLatency() {
        var analysis = new MailLatencyAnalysis();
        await analysis.AnalyzeServer("smtp.gmail.com", 25, new InternalLogger());
        if (analysis.ServerResults.TryGetValue("smtp.gmail.com:25", out var result)) {
            Helpers.ShowPropertiesTable("Mail Latency", result);
        }
    }
}

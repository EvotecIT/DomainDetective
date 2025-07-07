using System.Threading.Tasks;

namespace DomainDetective.Example;

public static partial class Program {
    /// <summary>
    /// Example analyzing IMAP server TLS configuration.
    /// </summary>
    public static async Task ExampleAnalyseImapTls() {
        var analysis = new IMAPTLSAnalysis();
        await analysis.AnalyzeServer("imap.gmail.com", 993, new InternalLogger());
        if (analysis.ServerResults.TryGetValue("imap.gmail.com:993", out var result)) {
            Helpers.ShowPropertiesTable("IMAP TLS", result);
        }
    }
}

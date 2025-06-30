using System.Threading.Tasks;

namespace DomainDetective.Example;

public static partial class Program {
    public static async Task ExampleAnalysePop3Tls() {
        var analysis = new POP3TLSAnalysis();
        await analysis.AnalyzeServer("pop.gmail.com", 995, new InternalLogger());
        if (analysis.ServerResults.TryGetValue("pop.gmail.com:995", out var result)) {
            Helpers.ShowPropertiesTable("POP3 TLS", result);
        }
    }
}

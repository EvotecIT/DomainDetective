using System.Threading.Tasks;

namespace DomainDetective.Example;

public static partial class Program {
    public static async Task ExampleAnalyseSmtpTls() {
        var analysis = new SMTPTLSAnalysis();
        await analysis.AnalyzeServer("smtp.gmail.com", 587, new InternalLogger());
        if (analysis.ServerResults.TryGetValue("smtp.gmail.com:587", out var result)) {
            Helpers.ShowPropertiesTable("SMTP TLS", result);
        }
    }
}
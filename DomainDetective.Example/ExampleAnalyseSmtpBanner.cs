using System.Threading.Tasks;

namespace DomainDetective.Example;

public static partial class Program {
    /// <summary>
    /// Example analyzing SMTP banner for a server.
    /// </summary>
    public static async Task ExampleAnalyseSmtpBanner() {
        var analysis = new SMTPBannerAnalysis { ExpectedHostname = "smtp.gmail.com" };
        await analysis.AnalyzeServer("smtp.gmail.com", 25, new InternalLogger());
        if (analysis.ServerResults.TryGetValue("smtp.gmail.com:25", out var result)) {
            Helpers.ShowPropertiesTable("SMTP Banner", result);
        }
    }
}


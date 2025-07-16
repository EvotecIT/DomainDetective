using System.Threading.Tasks;

namespace DomainDetective.Example;

public static partial class Program {
    public static async Task ExampleAnalyseTyposquatting() {
        var healthCheck = new DomainHealthCheck();
        healthCheck.Verbose = false;
        healthCheck.TyposquattingAnalysis.BrandKeywords.Add("paypal");
        healthCheck.TyposquattingAnalysis.BrandKeywords.Add("google");
        await healthCheck.VerifyTyposquatting("example.com");
        Helpers.ShowPropertiesTable("Typosquatting for example.com", healthCheck.TyposquattingAnalysis);
    }
}

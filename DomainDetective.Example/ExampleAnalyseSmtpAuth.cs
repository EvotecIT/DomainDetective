using System.Threading.Tasks;

namespace DomainDetective.Example;

public static partial class Program
{
    /// <summary>
    /// Example analyzing SMTP AUTH mechanisms.
    /// </summary>
    public static async Task ExampleAnalyseSmtpAuth()
    {
        var analysis = new SmtpAuthAnalysis { InspectCapabilities = true };
        await analysis.AnalyzeServer("smtp.gmail.com", 587, new InternalLogger());
        Helpers.ShowPropertiesTable("SMTP AUTH", analysis.ServerMechanisms);
    }
}

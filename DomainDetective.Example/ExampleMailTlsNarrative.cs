using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Narratives;

namespace DomainDetective.Example
{
    public static partial class Program
    {
        /// <summary>
        /// Demonstrates building a narrative from SMTP TLS analysis.
        /// </summary>
        public static async Task ExampleMailTlsNarrative()
        {
            var analysis = new SMTPTLSAnalysis();
            await analysis.AnalyzeServer("smtp.gmail.com", 587, new InternalLogger());
            var sections = MailTlsNarrative.Build(analysis, MailTlsAnalysis.MailProtocol.Smtp);
            Helpers.ShowPropertiesTable("SMTP TLS Narrative", sections);
        }
    }
}

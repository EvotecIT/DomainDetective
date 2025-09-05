using System;
using System.Threading.Tasks;
using DomainDetective.Narratives;

namespace DomainDetective.Example
{
    public static class ExampleWebsiteNarrative
    {
        public static async Task Run()
        {
            var logger = new InternalLogger();
            var http = new HttpAnalysis { Subject = "example.com" };
            await http.AnalyzeUrl("https://example.com", checkHsts: true, logger, collectHeaders: true);
            using var tls = new TlsAnalysis { Subject = "example.com" };
            await tls.AnalyzeServer("example.com", 443, logger);
            var sections = WebsiteNarrative.Build(http, tls);
            Console.WriteLine(sections.Title);
        }
    }
}


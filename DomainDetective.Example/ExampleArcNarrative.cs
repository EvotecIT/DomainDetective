using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Narratives;

namespace DomainDetective.Example;

public static partial class Program
{
    /// <summary>
    /// Demonstrates building an ARC narrative from raw headers.
    /// </summary>
    public static Task ExampleArcNarrative()
    {
        var rawHeaders = "ARC-Seal: i=1; a=rsa-sha256; b=ABC; d=example.org; s=arc;\r\n" +
                         "ARC-Authentication-Results: i=1; example.org; dkim=pass header.d=example.org; spf=pass smtp.mailfrom=example.org\r\n";
        var analysis = new ARCAnalysis();
        analysis.Analyze(rawHeaders);
        var narrative = ArcNarrative.Build(analysis);
        Helpers.ShowPropertiesTable("ARC Narrative", narrative);
        return Task.CompletedTask;
    }
}

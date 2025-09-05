using System.Threading.Tasks;

namespace DomainDetective.Example;

public static partial class Program
{
    /// <summary>
    /// Example parsing raw email headers.
    /// </summary>
    public static Task ExampleAnalyseMessageHeader()
    {
        var raw = "From: sender@example.com\nTo: recipient@example.com\nSubject: Test Message\nDate: Tue, 24 Oct 2023 12:34:56 +0000\nAuthentication-Results: mx.example.net; dkim=pass; spf=pass; dmarc=pass; arc=pass";
        var analysis = new MessageHeaderAnalysis();
        analysis.Parse(raw, new InternalLogger());
        Helpers.ShowPropertiesTable("Headers", analysis.Headers);
        return Task.CompletedTask;
    }
}

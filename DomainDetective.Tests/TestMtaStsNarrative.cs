using DnsClientX;
using DomainDetective;
using DomainDetective.Narratives;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace DomainDetective.Tests;

public class TestMtaStsNarrative
{
    [Fact]
    public async Task BuildsNarrativeWithHighlights()
    {
        Skip.If(!HttpListener.IsSupported, "HttpListener not supported");
        using var listener = new HttpListener();
        var port = PortHelper.GetFreePort();
        var prefix = $"http://localhost:{port}/";
        listener.Prefixes.Add(prefix);
        listener.Start();
        const string policy = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400";
        var serverTask = Task.Run(async () => {
            var ctx = await listener.GetContextAsync();
            if (ctx.Request.Url?.AbsolutePath == "/.well-known/mta-sts.txt") {
                var data = Encoding.UTF8.GetBytes(policy);
                ctx.Response.StatusCode = 200;
                await ctx.Response.OutputStream.WriteAsync(data, 0, data.Length);
            } else {
                ctx.Response.StatusCode = 404;
            }
            ctx.Response.Close();
        });
        try {
            var answers = new[] { new DnsAnswer { DataRaw = "v=STSv1; id=abc", Type = DnsRecordType.TXT } };
            var analysis = new MTASTSAnalysis {
                PolicyUrlOverride = prefix + ".well-known/mta-sts.txt",
                QueryDnsOverride = (_, _) => Task.FromResult(answers),
                DnsConfiguration = new DnsConfiguration()
            };
            await analysis.AnalyzePolicy("example.com", new InternalLogger());
            var sections = MtaStsNarrative.Build(analysis);
            Assert.Contains(sections.Highlights, h => h.Contains("MTA-STS record"));
            Assert.Contains(sections.Highlights, h => h.Contains("Policy mode: enforce"));
            Assert.Contains(sections.Highlights, h => h.Contains("Max age: 86400"));
        } finally {
            listener.Stop();
            await serverTask;
            PortHelper.ReleasePort(port);
        }
    }

    [Fact]
    public void HandlesNullAnalysis()
    {
        var sections = MtaStsNarrative.Build(null!);
        Assert.Contains("No MTA-STS data available", sections.Highlights[0]);
        Assert.Empty(sections.Positives);
    }

    [Fact]
    public void HandlesEmptyAssessments()
    {
        var analysis = new MTASTSAnalysis();
        var sections = MtaStsNarrative.Build(analysis, Array.Empty<Assessment>());
        Assert.Empty(sections.Positives);
        Assert.Empty(sections.Remediations);
    }
}

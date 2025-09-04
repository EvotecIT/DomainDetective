using System.Net;
using System.Threading.Tasks;
using DomainDetective.Narratives;
using Xunit;

namespace DomainDetective.Tests;

[Collection("HttpListener")]
public class TestDirectoryExposureNarrative
{
    [Fact]
    public async Task NarrativeHighlightsExposedPaths()
    {
        Skip.If(!HttpListener.IsSupported, "HttpListener not supported");
        using var listener = new HttpListener();
        var port = PortHelper.GetFreePort();
        var prefix = $"http://localhost:{port}/";
        listener.Prefixes.Add(prefix);
        listener.Start();
        PortHelper.ReleasePort(port);
        var serverTask = Task.Run(async () =>
        {
            while (listener.IsListening)
            {
                var ctx = await listener.GetContextAsync();
                if (ctx.Request.Url?.AbsolutePath.StartsWith("/.git") == true)
                    ctx.Response.StatusCode = 200;
                else
                    ctx.Response.StatusCode = 404;
                ctx.Response.Close();
            }
        });
        try
        {
            var hc = new DomainHealthCheck();
            await hc.VerifyDirectoryExposure(prefix.Replace("http://", string.Empty).TrimEnd('/'));
            var sections = DirectoryExposureNarrative.Build(hc.DirectoryExposureAnalysis);
            Assert.Contains(sections.Highlights, h => h.Contains(".git"));
        }
        finally
        {
            listener.Stop();
            await Task.Delay(50);
        }
    }

    [Fact]
    public async Task NarrativeIncludesPositiveAdviceWhenBrowsingDisabled()
    {
        Skip.If(!HttpListener.IsSupported, "HttpListener not supported");
        using var listener = new HttpListener();
        var port = PortHelper.GetFreePort();
        var prefix = $"http://localhost:{port}/";
        listener.Prefixes.Add(prefix);
        listener.Start();
        PortHelper.ReleasePort(port);
        var serverTask = Task.Run(async () =>
        {
            while (listener.IsListening)
            {
                var ctx = await listener.GetContextAsync();
                ctx.Response.StatusCode = 404;
                ctx.Response.Close();
            }
        });
        try
        {
            var hc = new DomainHealthCheck();
            await hc.VerifyDirectoryExposure(prefix.Replace("http://", string.Empty).TrimEnd('/'));
            var sections = DirectoryExposureNarrative.Build(hc.DirectoryExposureAnalysis);
            Assert.Contains(sections.Positives, p => p.Contains("Directory browsing disabled"));
        }
        finally
        {
            listener.Stop();
            await Task.Delay(50);
        }
    }
}

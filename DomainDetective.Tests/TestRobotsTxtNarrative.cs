using System.Net;
using System.Text;
using System.Threading.Tasks;
using DomainDetective.Narratives;
using Xunit;
using Xunit.Sdk;

namespace DomainDetective.Tests;

[Collection("HttpListener")]
public class TestRobotsTxtNarrative
{
    [Fact]
    public async Task BuildsNarrativeWithHighlightsAndPositives()
    {
        using var listener = StartListener(out var prefix);
        var content = "User-agent: *\nDisallow: /private\nSitemap: https://example.com/sitemap.xml";
        var serverTask = Task.Run(async () =>
        {
            try
            {
                var ctx = await listener.GetContextAsync();
                ctx.Response.StatusCode = 200;
                ctx.Response.ContentType = "text/plain";
                var buffer = Encoding.UTF8.GetBytes(content);
                await ctx.Response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                ctx.Response.Close();
            }
            catch (ObjectDisposedException)
            {
            }
            catch (HttpListenerException)
            {
            }
        });

        try
        {
            var healthCheck = new DomainHealthCheck();
            await healthCheck.Verify(prefix.Replace("http://", string.Empty).TrimEnd('/'), new[] { HealthCheckType.ROBOTS });
            var sections = RobotsTxtNarrative.Build(healthCheck.RobotsTxtAnalysis, healthCheck.RobotsTxtAnalysis.Assessments);
            Assert.Contains(sections.Highlights, h => h.Contains("robots.txt"));
            Assert.Contains(sections.Highlights, h => h.Contains("Disallow"));
            Assert.Contains(sections.Highlights, h => h.Contains("Sitemaps referenced"));
            Assert.NotEmpty(sections.Positives);
        }
        finally
        {
            listener.Stop();
            await serverTask;
        }
    }

    private static int GetFreePort() => PortHelper.GetFreePort();

    private static HttpListener StartListener(out string prefix)
    {
        Skip.If(!HttpListener.IsSupported, "HttpListener not supported");

        while (true)
        {
            var port = GetFreePort();
            prefix = $"http://127.0.0.1:{port}/";
            var l = new HttpListener();
            l.Prefixes.Add(prefix);
            try
            {
                l.Start();
                PortHelper.ReleasePort(port);
                return l;
            }
            catch (HttpListenerException)
            {
                l.Close();
                PortHelper.ReleasePort(port);
            }
        }
    }
}


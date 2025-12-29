using System.Net;
using System.Reflection;
using System.Threading.Tasks;
using Xunit.Sdk;

namespace DomainDetective.Tests;

[Collection("HttpListener")]
public class TestDirectoryExposureAnalysis
{
    [Fact]
    public async Task DetectsAccessibleDirectories()
    {
        Skip.If(!HttpListener.IsSupported, "HttpListener not supported");
        using var listener = new HttpListener();
        var port = GetFreePort();
        var prefix = $"http://localhost:{port}/";
        listener.Prefixes.Add(prefix);
        listener.Start();
        PortHelper.ReleasePort(port);
        var expectedRequests = GetExpectedRequestCount();
        var requestCount = 0;
        var serverTask = Task.Run(async () =>
        {
            // DirectoryExposureAnalysis probes multiple paths, so serve all requests
            // until the expected count is reached or the listener is stopped.
            while (listener.IsListening && requestCount < expectedRequests)
            {
                HttpListenerContext? ctx = null;
                try
                {
                    ctx = await listener.GetContextAsync();
                }
                catch
                {
                    break;
                }

                if (ctx == null)
                {
                    continue;
                }

                requestCount++;
                if (ctx.Request.Url?.AbsolutePath.StartsWith("/.git") == true)  
                {
                    ctx.Response.StatusCode = 200;
                }
                else
                {
                    ctx.Response.StatusCode = 404;
                }
                ctx.Response.Close();
            }
        });

        try
        {
            var hc = new DomainHealthCheck();
            await hc.VerifyDirectoryExposure(prefix.Replace("http://", string.Empty).TrimEnd('/'));
            Assert.Contains(".git/", hc.DirectoryExposureAnalysis.ExposedPaths);
        }
        finally
        {
            listener.Stop();
            await Task.Delay(50);
        }
    }

    [Fact]
    public async Task NoExposedDirectoriesWhenNoneAccessible()
    {
        Skip.If(!HttpListener.IsSupported, "HttpListener not supported");
        using var listener = new HttpListener();
        var port2 = GetFreePort();
        var prefix = $"http://localhost:{port2}/";
        listener.Prefixes.Add(prefix);
        listener.Start();
        PortHelper.ReleasePort(port2);
        var expectedRequests = GetExpectedRequestCount();
        var requestCount = 0;
        var serverTask = Task.Run(async () =>
        {
            // DirectoryExposureAnalysis probes multiple paths, so serve all requests
            // until the listener is stopped in the teardown.
            while (listener.IsListening && requestCount < expectedRequests)
            {
                HttpListenerContext? ctx = null;
                try
                {
                    ctx = await listener.GetContextAsync();
                }
                catch
                {
                    break;
                }

                if (ctx == null)
                {
                    continue;
                }

                requestCount++;
                ctx.Response.StatusCode = 404;
                ctx.Response.Close();
            }
        });

        try
        {
            var hc = new DomainHealthCheck();
            await hc.VerifyDirectoryExposure(prefix.Replace("http://", string.Empty).TrimEnd('/'));
            Assert.Empty(hc.DirectoryExposureAnalysis.ExposedPaths);
        }
        finally
        {
            listener.Stop();
            await Task.Delay(50);
        }
    }

    private static int GetFreePort() => PortHelper.GetFreePort();

    private static int GetExpectedRequestCount()
    {
        try
        {
            var field = typeof(DirectoryExposureAnalysis).GetField("_defaultPaths", BindingFlags.NonPublic | BindingFlags.Static);
            var paths = field?.GetValue(null) as string[];
            if (paths != null && paths.Length > 0)
            {
                return paths.Length;
            }
        }
        catch
        {
            // Fallback below.
        }

        return 20;
    }
}

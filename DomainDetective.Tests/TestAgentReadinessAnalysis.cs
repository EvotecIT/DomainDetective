using System.Net;
using System.Text;
using DomainDetective.DesiredState;
using Xunit.Sdk;

namespace DomainDetective.Tests;

[Collection("HttpListener")]
public class TestAgentReadinessAnalysis {
    [Fact]
    public async Task AnalyzeAsyncDetectsAgentDiscoveryResources() {
        using var listener = StartListener(out var prefix);
        using var cts = new CancellationTokenSource();
        var serverTask = RunAgentReadyServer(listener, cts.Token);

        try {
            var analysis = new AgentReadinessAnalysis();
            await analysis.AnalyzeAsync(prefix, cancellationToken: cts.Token);

            Assert.True(analysis.RobotsPresent);
            Assert.NotNull(analysis.Robots);
            Assert.Contains("https://example.com/sitemap.xml", analysis.Robots!.Sitemaps);
            Assert.NotEmpty(analysis.ContentSignals);
            Assert.Contains(analysis.LinkRelations, link => link.Relation == "api-catalog");
            Assert.Contains(analysis.LinkRelations, link => link.Relation == "alternate" && link.Type == "text/markdown");
            Assert.Contains(analysis.EndpointProbes, probe => probe.Kind == "llms.txt" && probe.Present);
            Assert.Contains(analysis.EndpointProbes, probe => probe.Kind == "api-catalog" && probe.Present && probe.ValidJson && probe.ShapeValid);
            Assert.Contains(analysis.EndpointProbes, probe => probe.Kind == "agent-skills" && probe.Present && probe.ValidJson && probe.ShapeValid);
            Assert.Contains(analysis.EndpointProbes, probe => probe.Kind == "agents-json" && probe.Present && probe.ValidJson && probe.ShapeValid);
            Assert.Contains(analysis.EndpointProbes, probe => probe.Kind == "openapi" && probe.Present && probe.ValidJson && probe.ShapeValid);
            Assert.Contains(analysis.EndpointProbes, probe => probe.Kind == "openapi" && probe.DiscoverySource == "api-catalog" && probe.Url.EndsWith("/catalog-openapi.json", StringComparison.OrdinalIgnoreCase));
            Assert.False(analysis.Markdown.DirectMarkdown);
            Assert.NotNull(analysis.Markdown.AlternateMarkdownUrl);
            Assert.True(analysis.Score > 50);
        } finally {
            cts.Cancel();
            listener.Stop();
            await serverTask;
        }
    }

    [Fact]
    public async Task ConvertReturnsScoreAndEvidence() {
        using var listener = StartListener(out var prefix);
        using var cts = new CancellationTokenSource();
        var serverTask = RunAgentReadyServer(listener, cts.Token);

        try {
            var analysis = new AgentReadinessAnalysis();
            await analysis.AnalyzeAsync(prefix, cancellationToken: cts.Token);

            var info = DomainDetective.Views.Converters.Convert(analysis);

            Assert.Equal(HealthCheckType.AGENTREADINESS, info.Check);
            Assert.True(info.RobotsPresent);
            Assert.True(info.LlmsTxtPresent);
            Assert.True(info.Score > 50);
            Assert.NotEmpty(info.Checks);
            Assert.NotEmpty(info.CategoryScores);
            Assert.Contains(info.Narrative.Highlights, highlight => highlight.Contains("score", StringComparison.OrdinalIgnoreCase));
        } finally {
            cts.Cancel();
            listener.Stop();
            await serverTask;
        }
    }

    [Fact]
    public async Task VerifyIncludesAgentReadinessAssessmentsInAggregateRecommendations() {
        using var listener = StartListener(out var prefix);
        using var cts = new CancellationTokenSource();
        var serverTask = RunAgentReadyServer(listener, cts.Token);

        try {
            var healthCheck = new DomainHealthCheck();
            await healthCheck.Verify(prefix.Replace("http://", string.Empty).TrimEnd('/'), new[] { HealthCheckType.AGENTREADINESS }, cancellationToken: cts.Token);

            Assert.Contains(healthCheck.GetAllAssessments(), assessment => assessment.Code == AgentReadinessCodes.LlmsTxtPresent);
            Assert.Contains(healthCheck.RecommendationViews, view => view.Code == AgentReadinessCodes.ContentSignalsPresent);
        } finally {
            cts.Cancel();
            listener.Stop();
            await serverTask;
        }
    }

    [Fact]
    public void LinkHeaderParserHandlesQuotedCommasAndRelativeTargets() {
        var source = new Uri("https://example.com/docs/");
        var links = AgentReadinessLinkHeaderParser.Parse(
            "</.well-known/api-catalog>; rel=\"api-catalog\"; type=\"application/linkset+json\"; title=\"API, Catalog\", </index.md>; rel=\"alternate\"; type=\"text/markdown\"",
            source);

        Assert.Contains(links, link => link.Relation == "api-catalog" && link.Target == "https://example.com/.well-known/api-catalog");
        Assert.Contains(links, link => link.Relation == "alternate" && link.Target == "https://example.com/index.md" && link.Type == "text/markdown");
    }

    [Fact]
    public async Task DesiredStateEvaluatesAgentReadinessPolicy() {
        using var listener = StartListener(out var prefix);
        using var cts = new CancellationTokenSource();
        var serverTask = RunAgentReadyServer(listener, cts.Token);

        try {
            var healthCheck = new DomainHealthCheck();
            await healthCheck.AgentReadinessAnalysis.AnalyzeAsync(prefix, cancellationToken: cts.Token);

            var profile = new DesiredStateProfile {
                AgentReadiness = new DesiredStateAgentReadinessPolicy {
                    Enabled = true,
                    MinimumScore = 50,
                    RequireRobotsTxt = true,
                    RequireSitemap = true,
                    RequireLinkHeaders = true,
                    RequireLlmsTxt = true,
                    RequireMarkdown = true,
                    RequireContentSignals = true,
                    RequireAiBotRules = true,
                    RequireApiCatalog = true,
                    RequireAgentSkills = true,
                    RequireAgentsJson = true,
                    RequireOpenApi = true,
                    MinTrustHeaders = 5
                }
            };

            Assert.Contains(HealthCheckType.AGENTREADINESS, DesiredStateConfiguration.GetRequiredChecks(profile));

            var desired = DesiredStateEvaluator.Evaluate("127.0.0.1", healthCheck, profile);

            Assert.True(desired.Conforms);
            Assert.DoesNotContain(desired.Assessments, assessment => assessment.Code == DesiredStateCodes.AgentReadinessLlmsTxtMissing);
            Assert.Contains(desired.Assessments, assessment => assessment.Code == DesiredStateCodes.Conforms);
        } finally {
            cts.Cancel();
            listener.Stop();
            await serverTask;
        }
    }

    [Fact]
    public async Task AnalyzeAsyncDoesNotScoreHttpErrorMainPage() {
        using var listener = StartListener(out var prefix);
        using var cts = new CancellationTokenSource();
        var serverTask = RunAgentReadyServer(listener, cts.Token);

        try {
            var analysis = new AgentReadinessAnalysis();
            await analysis.AnalyzeAsync(prefix + "missing", cancellationToken: cts.Token);

            Assert.Equal(404, analysis.MainPageStatusCode);
            Assert.Equal(0, analysis.Score);
            Assert.Contains(analysis.Checks, check => check.Code == AgentReadinessCodes.MainPageFailed && check.Status == AgentReadinessCheckStatus.Fail);
            Assert.Empty(analysis.EndpointProbes);
        } finally {
            cts.Cancel();
            listener.Stop();
            await serverTask;
        }
    }

    [Fact]
    public async Task AnalyzeAsyncPropagatesCancellation() {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var analysis = new AgentReadinessAnalysis();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            analysis.AnalyzeAsync("https://example.com/", cancellationToken: cts.Token));
    }

    private static async Task RunAgentReadyServer(HttpListener listener, CancellationToken cancellationToken) {
        while (!cancellationToken.IsCancellationRequested) {
            HttpListenerContext ctx;
            try {
                ctx = await listener.GetContextAsync();
            } catch (ObjectDisposedException) {
                break;
            } catch (HttpListenerException) {
                break;
            }

            await Respond(ctx);
        }
    }

    private static async Task Respond(HttpListenerContext ctx) {
        var path = ctx.Request.Url?.AbsolutePath ?? "/";
        ctx.Response.Headers.Add("Strict-Transport-Security", "max-age=31536000");
        ctx.Response.Headers.Add("Content-Security-Policy", "default-src 'self'");
        ctx.Response.Headers.Add("X-Content-Type-Options", "nosniff");
        ctx.Response.Headers.Add("X-Frame-Options", "SAMEORIGIN");
        ctx.Response.Headers.Add("Referrer-Policy", "strict-origin-when-cross-origin");

        switch (path) {
            case "/":
                ctx.Response.ContentType = "text/html";
                ctx.Response.Headers.Add(
                    "Link",
                    "</.well-known/api-catalog>; rel=\"api-catalog\"; type=\"application/linkset+json\", </.well-known/agent-skills/index.json>; rel=\"describedby\"; type=\"application/json\", </index.md>; rel=\"alternate\"; type=\"text/markdown\", </llms.txt>; rel=\"service-doc\"; type=\"text/plain\"");
                ctx.Response.Headers.Add("Content-Signal", "search=yes, ai-input=yes, ai-train=no");
                await Write(ctx, "<!doctype html><html lang=\"en\"><head><title>Example</title><meta name=\"description\" content=\"Agent ready example\"></head><body><main><h1>Example</h1></main></body></html>");
                break;
            case "/robots.txt":
                ctx.Response.ContentType = "text/plain";
                await Write(ctx, "User-agent: *\nAllow: /\nSitemap: https://example.com/sitemap.xml\nUser-agent: GPTBot\nAllow: /\nContent-Signal: search=yes, ai-input=yes, ai-train=no\n");
                break;
            case "/llms.txt":
                ctx.Response.ContentType = "text/plain";
                await Write(ctx, "# Example\n\n- /.well-known/api-catalog\n");
                break;
            case "/index.md":
                ctx.Response.ContentType = "text/markdown";
                await Write(ctx, "# Example\n\nMarkdown page.\n");
                break;
            case "/.well-known/api-catalog":
                ctx.Response.ContentType = "application/linkset+json";
                await Write(ctx, "{\"linkset\":[{\"anchor\":\"https://example.com\",\"openapi\":[{\"href\":\"/catalog-openapi.json\"}]}]}");
                break;
            case "/.well-known/agent-skills/index.json":
                ctx.Response.ContentType = "application/json";
                await Write(ctx, "{\"skills\":[{\"name\":\"site-assistant\",\"url\":\"/.well-known/agent-skills/site/SKILL.md\"}]}");
                break;
            case "/agents.json":
                ctx.Response.ContentType = "application/json";
                await Write(ctx, "{\"name\":\"Example\",\"resources\":{\"llms\":\"/llms.txt\",\"apiCatalog\":\"/.well-known/api-catalog\"}}");
                break;
            case "/openapi.json":
            case "/catalog-openapi.json":
                ctx.Response.ContentType = "application/json";
                await Write(ctx, "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"Example\",\"version\":\"1.0.0\"},\"paths\":{}}");
                break;
            default:
                ctx.Response.StatusCode = 404;
                ctx.Response.Close();
                break;
        }
    }

    private static async Task Write(HttpListenerContext ctx, string content) {
        var bytes = Encoding.UTF8.GetBytes(content);
        ctx.Response.ContentLength64 = bytes.Length;
        await ctx.Response.OutputStream.WriteAsync(bytes, 0, bytes.Length);
        ctx.Response.Close();
    }

    private static HttpListener StartListener(out string prefix) {
        Skip.If(!HttpListener.IsSupported, "HttpListener not supported");

        while (true) {
            var port = PortHelper.GetFreePort();
            prefix = $"http://127.0.0.1:{port}/";
            var listener = new HttpListener();
            listener.Prefixes.Add(prefix);
            try {
                listener.Start();
                PortHelper.ReleasePort(port);
                return listener;
            } catch (HttpListenerException) {
                listener.Close();
                PortHelper.ReleasePort(port);
            }
        }
    }
}

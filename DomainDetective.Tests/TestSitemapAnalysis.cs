using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Text;
using Xunit.Sdk;

namespace DomainDetective.Tests;

[Collection("HttpListener")]
public class TestSitemapAnalysis {
    [Fact]
    public async Task AnalyzeAsyncParsesSitemapAndDetectsUrlProblems() {
        using var listener = StartListener(out var prefix);
        using var cts = new CancellationTokenSource();
        var serverTask = RunSitemapServer(listener, prefix, cts.Token);

        try {
            var analysis = new SitemapAnalysis();
            var options = new SitemapAnalysisOptions {
                MaxUrlProbes = 10,
                MaxEntries = 20,
                MaxSitemapDocuments = 5
            };

            await analysis.AnalyzeAsync(prefix, options: options, cancellationToken: cts.Token);

            Assert.Single(analysis.Documents);
            Assert.True(analysis.Documents[0].XmlValid);
            Assert.Equal(SitemapDocumentKind.UrlSet, analysis.Documents[0].Kind);
            Assert.Equal(6, analysis.Entries.Count);
            Assert.Equal(1, analysis.DuplicateLocationCount);
            Assert.Equal(1, analysis.RedirectLoopCount);
            Assert.Equal(1, analysis.ClientErrorCount);
            Assert.Equal(1, analysis.NoIndexCount);
            Assert.Equal(1, analysis.CanonicalMismatchCount);
            Assert.Contains(analysis.UrlProbes, probe => probe.Url.EndsWith("/loop/", StringComparison.OrdinalIgnoreCase) && probe.RedirectLoop);
            Assert.Contains(analysis.Assessments, assessment => assessment.Code == SitemapCodes.UrlRedirectLoop);
            Assert.Contains(analysis.Assessments, assessment => assessment.Code == SitemapCodes.UrlClientError);
            Assert.Contains(analysis.Assessments, assessment => assessment.Code == SitemapCodes.UrlNoIndex);
            Assert.Contains(analysis.Assessments, assessment => assessment.Code == SitemapCodes.CanonicalMismatch);
        } finally {
            cts.Cancel();
            listener.Stop();
            await serverTask;
        }
    }

    [Fact]
    public async Task VerifyIncludesSitemapAssessmentsInAggregateRecommendations() {
        using var listener = StartListener(out var prefix);
        using var cts = new CancellationTokenSource();
        var serverTask = RunSitemapServer(listener, prefix, cts.Token);

        try {
            var healthCheck = new DomainHealthCheck();
            await healthCheck.Verify(prefix.Replace("http://", string.Empty).TrimEnd('/'), new[] { HealthCheckType.SITEMAP }, cancellationToken: cts.Token);

            Assert.Contains(healthCheck.GetAllAssessments(), assessment => assessment.Code == SitemapCodes.UrlRedirectLoop);
            Assert.Contains(healthCheck.RecommendationViews, view => view.Code == SitemapCodes.UrlRedirectLoop);
            Assert.Same(healthCheck.SitemapAnalysis, healthCheck.GetAnalysisMap()[HealthCheckType.SITEMAP]);
        } finally {
            cts.Cancel();
            listener.Stop();
            await serverTask;
        }
    }

    [Fact]
    public void ConvertReturnsSitemapSummary() {
        var analysis = new SitemapAnalysis();
        analysis.Assessments.Add(new Assessment {
            Severity = AssessmentSeverity.Warning,
            Category = "Sitemap",
            Target = "example.com",
            Code = SitemapCodes.UrlRedirect,
            Message = "Sitemap URL redirects."
        });
        analysis.Documents.Add(new SitemapDocument {
            Url = "https://example.com/sitemap.xml",
            Present = true,
            XmlValid = true,
            NamespaceValid = true,
            Kind = SitemapDocumentKind.UrlSet,
            UrlCount = 1
        });
        analysis.Entries.Add(new SitemapUrlEntry {
            SitemapUrl = "https://example.com/sitemap.xml",
            Location = "https://example.com/"
        });

        var info = DomainDetective.Views.Converters.Convert(analysis);

        Assert.Equal(HealthCheckType.SITEMAP, info.Check);
        Assert.Equal("Warning", info.Status);
        Assert.Equal(1, info.DocumentCount);
        Assert.Equal(1, info.UrlCount);
        Assert.Single(info.Documents);
    }

    [Fact]
    public async Task AnalyzeAsyncParsesLargeSitemapDocumentsWithoutTruncatingXml() {
        var largeSitemap = BuildLargeSitemap("https://large.example/", 4500);
        Assert.True(largeSitemap.Length > 262144);

        var analysis = new SitemapAnalysis {
            HttpHandlerFactory = () => new HttpStubMessageHandler((request, cancellationToken) => {
                var url = request.RequestUri?.AbsoluteUri ?? string.Empty;
                if (url.Equals("https://large.example/robots.txt", StringComparison.OrdinalIgnoreCase)) {
                    return CreateResponse("text/plain", "User-agent: *\nAllow: /\nSitemap: https://large.example/sitemap.xml\n");
                }

                if (url.Equals("https://large.example/sitemap.xml", StringComparison.OrdinalIgnoreCase)) {
                    return CreateResponse("application/xml", largeSitemap);
                }

                return new HttpResponseMessage(HttpStatusCode.NotFound);
            })
        };

        await analysis.AnalyzeAsync(
            "large.example",
            options: new SitemapAnalysisOptions {
                AllowHttpFallback = false,
                MaxEntries = 5000,
                ProbeUrls = false
            });

        Assert.Single(analysis.Documents);
        Assert.True(analysis.Documents[0].XmlValid);
        Assert.Equal(4500, analysis.Entries.Count);
        Assert.DoesNotContain(analysis.Assessments, assessment => assessment.Code == SitemapCodes.XmlInvalid);
    }

    [Fact]
    public async Task AnalyzeAsyncParsesGzipSitemapDocuments() {
        var sitemap = "<?xml version=\"1.0\"?><urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\"><url><loc>https://gzip.example/</loc></url></urlset>";
        var analysis = new SitemapAnalysis {
            HttpHandlerFactory = () => new HttpStubMessageHandler((request, cancellationToken) => {
                var url = request.RequestUri?.AbsoluteUri ?? string.Empty;
                if (url.Equals("https://gzip.example/robots.txt", StringComparison.OrdinalIgnoreCase)) {
                    return CreateResponse("text/plain", "User-agent: *\nAllow: /\nSitemap: https://gzip.example/sitemap.xml.gz\n");
                }

                if (url.Equals("https://gzip.example/sitemap.xml.gz", StringComparison.OrdinalIgnoreCase)) {
                    var response = new HttpResponseMessage(HttpStatusCode.OK) {
                        Content = new ByteArrayContent(CompressUtf8(sitemap))
                    };
                    response.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
                    return response;
                }

                return new HttpResponseMessage(HttpStatusCode.NotFound);
            })
        };

        await analysis.AnalyzeAsync(
            "gzip.example",
            options: new SitemapAnalysisOptions {
                AllowHttpFallback = false,
                ProbeUrls = false
            });

        Assert.Contains(analysis.Documents, document => document.Url == "https://gzip.example/sitemap.xml.gz" && document.XmlValid);
        Assert.Single(analysis.Entries);
        Assert.DoesNotContain(analysis.Assessments, assessment => assessment.Code == SitemapCodes.XmlInvalid);
    }

    [Fact]
    public async Task AnalyzeAsyncReportsMalformedGzipSitemapAsDownloadFailure() {
        var analysis = new SitemapAnalysis {
            HttpHandlerFactory = () => new HttpStubMessageHandler((request, cancellationToken) => {
                var url = request.RequestUri?.AbsoluteUri ?? string.Empty;
                if (url.Equals("https://badgzip.example/robots.txt", StringComparison.OrdinalIgnoreCase)) {
                    return CreateResponse("text/plain", "User-agent: *\nAllow: /\nSitemap: https://badgzip.example/sitemap.xml.gz\n");
                }

                if (url.Equals("https://badgzip.example/sitemap.xml.gz", StringComparison.OrdinalIgnoreCase)) {
                    var response = new HttpResponseMessage(HttpStatusCode.OK) {
                        Content = new ByteArrayContent(new byte[] { 0x1f, 0x8b, 0x08, 0x00 })
                    };
                    response.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
                    return response;
                }

                return new HttpResponseMessage(HttpStatusCode.NotFound);
            })
        };

        await analysis.AnalyzeAsync(
            "badgzip.example",
            options: new SitemapAnalysisOptions {
                AllowHttpFallback = false,
                ProbeUrls = false
            });

        Assert.Contains(analysis.Documents, document => document.Error != null && document.Error.IndexOf("gzip", StringComparison.OrdinalIgnoreCase) >= 0);
        Assert.Contains(analysis.Assessments, assessment => assessment.Code == SitemapCodes.DownloadFailed);
        Assert.DoesNotContain(analysis.Assessments, assessment => assessment.Code == SitemapCodes.XmlInvalid);
    }

    [Fact]
    public async Task AnalyzeAsyncRestrictsRobotsSitemapsWhenRequested() {
        var requestedUrls = new List<string>();
        var analysis = new SitemapAnalysis {
            HttpHandlerFactory = () => new HttpStubMessageHandler((request, cancellationToken) => {
                var url = request.RequestUri?.AbsoluteUri ?? string.Empty;
                requestedUrls.Add(url);
                if (url.Equals("https://safe.example/robots.txt", StringComparison.OrdinalIgnoreCase)) {
                    return CreateResponse("text/plain", "User-agent: *\nAllow: /\nSitemap: https://other.example/sitemap.xml\n");
                }

                return new HttpResponseMessage(HttpStatusCode.NotFound);
            })
        };

        await analysis.AnalyzeAsync(
            "safe.example",
            options: new SitemapAnalysisOptions {
                AllowHttpFallback = false,
                ProbeUrls = false,
                RestrictRemoteFetchesToOriginHost = true
            });

        Assert.DoesNotContain(requestedUrls, url => url.Equals("https://other.example/sitemap.xml", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(analysis.Assessments, assessment => assessment.Code == SitemapCodes.CrossHostSitemap);
    }

    [Fact]
    public async Task AnalyzeAsyncDoesNotProbeHttpFallbackWhenHttpsSitemapIsHealthy() {
        var requestedUrls = new List<string>();
        var analysis = new SitemapAnalysis {
            HttpHandlerFactory = () => new HttpStubMessageHandler((request, cancellationToken) => {
                var url = request.RequestUri?.AbsoluteUri ?? string.Empty;
                requestedUrls.Add(url);
                if (url.Equals("https://fallback.example/robots.txt", StringComparison.OrdinalIgnoreCase)) {
                    return CreateResponse("text/plain", "User-agent: *\nAllow: /\nSitemap: https://fallback.example/sitemap.xml\n");
                }

                if (url.Equals("https://fallback.example/sitemap.xml", StringComparison.OrdinalIgnoreCase)) {
                    return CreateResponse("application/xml", "<?xml version=\"1.0\"?><urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\"><url><loc>https://fallback.example/</loc></url></urlset>");
                }

                return new HttpResponseMessage(HttpStatusCode.NotFound);
            })
        };

        await analysis.AnalyzeAsync(
            "fallback.example",
            options: new SitemapAnalysisOptions {
                AllowHttpFallback = true,
                ProbeUrls = false
            });

        Assert.DoesNotContain(requestedUrls, url => url.StartsWith("http://fallback.example/", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(analysis.Documents, document => document.Url == "https://fallback.example/sitemap.xml" && document.XmlValid);
    }

    [Fact]
    public async Task AnalyzeAsyncDeduplicatesRedirectedSitemapDocumentsByFinalUri() {
        var sitemap = "<?xml version=\"1.0\"?><urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\"><url><loc>https://dedupe.example/</loc></url></urlset>";
        var analysis = new SitemapAnalysis {
            HttpHandlerFactory = () => new HttpStubMessageHandler((request, cancellationToken) => {
                var url = request.RequestUri?.AbsoluteUri ?? string.Empty;
                if (url.Equals("https://dedupe.example/robots.txt", StringComparison.OrdinalIgnoreCase)) {
                    return CreateResponse("text/plain", "User-agent: *\nAllow: /\nSitemap: https://dedupe.example/final.xml\n");
                }

                if (url.Equals("https://dedupe.example/sitemap.xml", StringComparison.OrdinalIgnoreCase)) {
                    var response = new HttpResponseMessage(HttpStatusCode.MovedPermanently);
                    response.Headers.Location = new Uri("https://dedupe.example/final.xml");
                    return response;
                }

                if (url.Equals("https://dedupe.example/final.xml", StringComparison.OrdinalIgnoreCase)) {
                    return CreateResponse("application/xml", sitemap);
                }

                return new HttpResponseMessage(HttpStatusCode.NotFound);
            })
        };

        await analysis.AnalyzeAsync(
            "dedupe.example",
            options: new SitemapAnalysisOptions {
                AllowHttpFallback = false,
                ProbeUrls = false
            });

        Assert.Single(analysis.Entries);
        Assert.Equal(0, analysis.DuplicateLocationCount);
    }

    [Fact]
    public async Task AnalyzeAsyncPropagatesCancellation() {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var analysis = new SitemapAnalysis {
            HttpHandlerFactory = () => new HttpStubMessageHandler((request, cancellationToken) => new HttpResponseMessage(HttpStatusCode.OK))
        };

        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            analysis.AnalyzeAsync("cancel.example", cancellationToken: cts.Token));
    }

    [Fact]
    public async Task AnalyzeAsyncReportsAccessForbiddenAsCrawlerAccessWarning() {
        var analysis = new SitemapAnalysis {
            HttpHandlerFactory = () => new HttpStubMessageHandler((request, cancellationToken) => {
                var url = request.RequestUri?.AbsoluteUri ?? string.Empty;
                if (url.Equals("https://blocked.example/robots.txt", StringComparison.OrdinalIgnoreCase)) {
                    return CreateResponse("text/plain", "User-agent: *\nAllow: /\nSitemap: https://blocked.example/sitemap.xml\n");
                }

                if (url.Equals("https://blocked.example/sitemap.xml", StringComparison.OrdinalIgnoreCase)) {
                    return CreateResponse("application/xml", "<?xml version=\"1.0\"?><urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\"><url><loc>https://blocked.example/lp/foundation-dns/</loc></url></urlset>");
                }

                if (url.Equals("https://blocked.example/lp/foundation-dns/", StringComparison.OrdinalIgnoreCase)) {
                    return new HttpResponseMessage(HttpStatusCode.Forbidden);
                }

                return new HttpResponseMessage(HttpStatusCode.NotFound);
            })
        };

        await analysis.AnalyzeAsync(
            "blocked.example",
            options: new SitemapAnalysisOptions {
                AllowHttpFallback = false,
                MaxUrlProbes = 10
            });

        Assert.Equal(1, analysis.ClientErrorCount);
        Assert.Contains(analysis.Assessments, assessment => assessment.Code == SitemapCodes.UrlAccessForbidden && assessment.Severity == AssessmentSeverity.Warning);
        Assert.DoesNotContain(analysis.Assessments, assessment => assessment.Code == SitemapCodes.UrlClientError && assessment.Target == "https://blocked.example/lp/foundation-dns/");
        Assert.Contains(analysis.Recommendations, recommendation => recommendation.Code == SitemapCodes.UrlAccessForbidden);
    }

    [Fact]
    public async Task AnalyzeAsyncWarnsWhenRobotsAdvertisesCrossHostSitemap() {
        var analysis = new SitemapAnalysis {
            HttpHandlerFactory = () => new HttpStubMessageHandler((request, cancellationToken) => {
                var url = request.RequestUri?.AbsoluteUri ?? string.Empty;
                if (url.Equals("https://example.test/robots.txt", StringComparison.OrdinalIgnoreCase)) {
                    return CreateResponse("text/plain", "User-agent: *\nAllow: /\nSitemap: https://other.example/sitemap.xml\n");
                }

                if (url.Equals("https://other.example/sitemap.xml", StringComparison.OrdinalIgnoreCase)) {
                    return CreateResponse("application/xml", "<?xml version=\"1.0\"?><urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\"><url><loc>https://other.example/</loc></url></urlset>");
                }

                return new HttpResponseMessage(HttpStatusCode.NotFound);
            })
        };

        await analysis.AnalyzeAsync(
            "example.test",
            options: new SitemapAnalysisOptions {
                AllowHttpFallback = false,
                ProbeUrls = false
            });

        Assert.Contains(analysis.Assessments, assessment => assessment.Code == SitemapCodes.CrossHostSitemap);
        Assert.Contains(analysis.Recommendations, recommendation => recommendation.Code == SitemapCodes.CrossHostSitemap);
    }

    [Fact]
    public async Task AnalyzeAsyncDoesNotWarnWhenRobotsAdvertisesWwwSitemap() {
        var analysis = new SitemapAnalysis {
            HttpHandlerFactory = () => new HttpStubMessageHandler((request, cancellationToken) => {
                var url = request.RequestUri?.AbsoluteUri ?? string.Empty;
                if (url.Equals("https://example.test/robots.txt", StringComparison.OrdinalIgnoreCase)) {
                    return CreateResponse("text/plain", "User-agent: *\nAllow: /\nSitemap: https://www.example.test/sitemap.xml\n");
                }

                if (url.Equals("https://www.example.test/sitemap.xml", StringComparison.OrdinalIgnoreCase)) {
                    return CreateResponse("application/xml", "<?xml version=\"1.0\"?><urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\"><url><loc>https://www.example.test/</loc></url></urlset>");
                }

                return new HttpResponseMessage(HttpStatusCode.NotFound);
            })
        };

        await analysis.AnalyzeAsync(
            "example.test",
            options: new SitemapAnalysisOptions {
                AllowHttpFallback = false,
                ProbeUrls = false
            });

        Assert.DoesNotContain(analysis.Assessments, assessment => assessment.Code == SitemapCodes.CrossHostSitemap);
    }

    private static async Task RunSitemapServer(HttpListener listener, string prefix, CancellationToken cancellationToken) {
        while (!cancellationToken.IsCancellationRequested) {
            HttpListenerContext ctx;
            try {
                ctx = await listener.GetContextAsync();
            } catch (ObjectDisposedException) {
                break;
            } catch (HttpListenerException) {
                break;
            }

            await Respond(ctx, prefix);
        }
    }

    private static async Task Respond(HttpListenerContext ctx, string prefix) {
        var path = ctx.Request.Url?.AbsolutePath ?? "/";
        switch (path) {
            case "/robots.txt":
                ctx.Response.ContentType = "text/plain";
                await Write(ctx, "User-agent: *\nAllow: /\nSitemap: " + prefix + "sitemap.xml\n");
                break;
            case "/sitemap.xml":
                ctx.Response.ContentType = "application/xml";
                await Write(ctx, BuildSitemap(prefix));
                break;
            case "/ok/":
                ctx.Response.ContentType = "text/html";
                await Write(ctx, "<!doctype html><html><head><link rel=\"canonical\" href=\"" + prefix + "ok/\"></head><body>OK</body></html>");
                break;
            case "/loop/":
                ctx.Response.StatusCode = 301;
                ctx.Response.RedirectLocation = prefix + "loop/";
                ctx.Response.Close();
                break;
            case "/missing/":
                ctx.Response.StatusCode = 404;
                ctx.Response.Close();
                break;
            case "/noindex/":
                ctx.Response.ContentType = "text/html";
                ctx.Response.Headers.Add("X-Robots-Tag", "noindex");
                await Write(ctx, "<!doctype html><html><body>No index</body></html>");
                break;
            case "/canonical-source/":
                ctx.Response.ContentType = "text/html";
                await Write(ctx, "<!doctype html><html><head><link rel=\"canonical\" href=\"" + prefix + "canonical-target/\"></head><body>Canonical elsewhere</body></html>");
                break;
            case "/canonical-target/":
                ctx.Response.ContentType = "text/html";
                await Write(ctx, "<!doctype html><html><body>Canonical target</body></html>");
                break;
            default:
                ctx.Response.StatusCode = 404;
                ctx.Response.Close();
                break;
        }
    }

    private static string BuildSitemap(string prefix) {
        return "<?xml version=\"1.0\" encoding=\"utf-8\"?>" +
               "<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">" +
               "<url><loc>" + prefix + "ok/</loc><lastmod>2026-05-07</lastmod><changefreq>daily</changefreq><priority>1.0</priority></url>" +
               "<url><loc>" + prefix + "loop/</loc><lastmod>2026-05-07</lastmod><changefreq>monthly</changefreq><priority>0.5</priority></url>" +
               "<url><loc>" + prefix + "missing/</loc><lastmod>2026-05-07</lastmod><changefreq>monthly</changefreq><priority>0.5</priority></url>" +
               "<url><loc>" + prefix + "noindex/</loc><lastmod>2026-05-07</lastmod><changefreq>monthly</changefreq><priority>0.5</priority></url>" +
               "<url><loc>" + prefix + "canonical-source/</loc><lastmod>2026-05-07</lastmod><changefreq>monthly</changefreq><priority>0.5</priority></url>" +
               "<url><loc>" + prefix + "ok/</loc><lastmod>2026-05-07</lastmod><changefreq>monthly</changefreq><priority>0.5</priority></url>" +
               "</urlset>";
    }

    private static string BuildLargeSitemap(string prefix, int count) {
        var builder = new StringBuilder();
        builder.Append("<?xml version=\"1.0\" encoding=\"utf-8\"?>");
        builder.Append("<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">");
        for (var i = 0; i < count; i++) {
            builder.Append("<url><loc>");
            builder.Append(prefix);
            builder.Append("page-");
            builder.Append(i);
            builder.Append("/</loc><lastmod>2026-05-07</lastmod><changefreq>monthly</changefreq><priority>0.5</priority></url>");
        }
        builder.Append("</urlset>");
        return builder.ToString();
    }

    private static byte[] CompressUtf8(string content) {
        using var output = new MemoryStream();
        using (var gzip = new GZipStream(output, CompressionMode.Compress, leaveOpen: true)) {
            var bytes = Encoding.UTF8.GetBytes(content);
            gzip.Write(bytes, 0, bytes.Length);
        }
        return output.ToArray();
    }

    private static async Task Write(HttpListenerContext ctx, string content) {
        var bytes = Encoding.UTF8.GetBytes(content);
        ctx.Response.ContentLength64 = bytes.Length;
        await ctx.Response.OutputStream.WriteAsync(bytes, 0, bytes.Length);
        ctx.Response.Close();
    }

    private static HttpResponseMessage CreateResponse(string contentType, string body) {
        return new HttpResponseMessage(HttpStatusCode.OK) {
            Content = new StringContent(body, Encoding.UTF8, contentType)
        };
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

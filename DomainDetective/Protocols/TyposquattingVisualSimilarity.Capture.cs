using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
#if NET8_0_OR_GREATER
using Microsoft.Playwright;
#endif

namespace DomainDetective;

/// <summary>
/// Default visual-asset capture helpers for typosquatting similarity.
/// </summary>
public static partial class TyposquattingVisualSimilarityAnalyzer
{
    private static readonly Regex LinkTagRegex = new("<link\\b[^>]*>", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex MetaTagRegex = new("<meta\\b[^>]*>", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static async Task<IReadOnlyList<TyposquattingVisualArtifact>> CaptureVisualArtifactsAsync(
        string url,
        TyposquattingCandidate? candidate,
        TyposquattingVisualSimilarityOptions options,
        CancellationToken cancellationToken)
    {
        if (options.CaptureManyOverride != null)
        {
            var overriddenArtifacts = await options.CaptureManyOverride(url, cancellationToken).ConfigureAwait(false);
            return overriddenArtifacts ?? Array.Empty<TyposquattingVisualArtifact>();
        }

        if (options.CaptureOverride != null)
        {
            var artifact = await options.CaptureOverride(url, cancellationToken).ConfigureAwait(false);
            if (artifact == null)
            {
                return Array.Empty<TyposquattingVisualArtifact>();
            }

            return new[] { artifact };
        }

        var artifacts = new List<TyposquattingVisualArtifact>();

        if (options.EnableBrowserCapture)
        {
            var screenshotArtifact = await CaptureBrowserArtifactAsync(url, options, cancellationToken).ConfigureAwait(false);
            if (screenshotArtifact != null)
            {
                artifacts.Add(screenshotArtifact);
            }
        }

        if (!options.EnableStaticAssetCapture)
        {
            return artifacts;
        }

        var page = candidate?.Enrichment?.Http;
        if (page == null || string.IsNullOrWhiteSpace(page.Body))
        {
            page = await BuildPageHttpAsync(url, options, cancellationToken).ConfigureAwait(false);
        }

        var assetCandidates = FindVisualAssetCandidates(url, page, options);
        if (assetCandidates.Count == 0)
        {
            return artifacts;
        }

        foreach (var assetCandidate in assetCandidates)
        {
            var artifact = await DownloadAssetAsync(assetCandidate, options, cancellationToken).ConfigureAwait(false);
            if (artifact != null)
            {
                artifacts.Add(artifact);
            }
        }

        return artifacts;
    }

    private static async Task<TyposquattingVisualArtifact?> CaptureBrowserArtifactAsync(
        string url,
        TyposquattingVisualSimilarityOptions options,
        CancellationToken cancellationToken)
    {
        if (options.BrowserCaptureOverride != null)
        {
            return await options.BrowserCaptureOverride(url, cancellationToken).ConfigureAwait(false);
        }

#if NET8_0_OR_GREATER
        try
        {
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            linkedCts.CancelAfter(options.BrowserCaptureTimeout);

            using var playwright = await Playwright.CreateAsync().ConfigureAwait(false);
            await using var browser = await playwright.Chromium.LaunchAsync(new BrowserTypeLaunchOptions
            {
                Headless = true
            }).ConfigureAwait(false);
            var context = await browser.NewContextAsync(new BrowserNewContextOptions
            {
                ViewportSize = new ViewportSize
                {
                    Width = Math.Max(320, options.BrowserViewportWidth),
                    Height = Math.Max(240, options.BrowserViewportHeight)
                },
                IgnoreHTTPSErrors = options.HttpRequestOptions.DisableTlsValidation
            }).ConfigureAwait(false);
            var page = await context.NewPageAsync().ConfigureAwait(false);
            await page.GotoAsync(url, new PageGotoOptions
            {
                WaitUntil = WaitUntilState.NetworkIdle,
                Timeout = (float)options.BrowserCaptureTimeout.TotalMilliseconds
            }).ConfigureAwait(false);

            if (options.BrowserPostLoadDelay > TimeSpan.Zero)
            {
                await page.WaitForTimeoutAsync((float)options.BrowserPostLoadDelay.TotalMilliseconds).ConfigureAwait(false);
            }

            var bytes = await page.ScreenshotAsync(new PageScreenshotOptions
            {
                FullPage = options.BrowserFullPageScreenshot,
                Type = ScreenshotType.Png
            }).ConfigureAwait(false);
            if (bytes == null || bytes.Length == 0)
            {
                return null;
            }

            var pageUrl = page.Url ?? url;
            return new TyposquattingVisualArtifact
            {
                ImageBytes = bytes,
                MimeType = "image/png",
                Kind = TyposquattingVisualArtifactKind.Screenshot,
                SourceUrl = pageUrl
            };
        }
        catch
        {
            return null;
        }
#else
        return null;
#endif
    }

    private static async Task<HttpAnalysis?> BuildPageHttpAsync(
        string url,
        TyposquattingVisualSimilarityOptions options,
        CancellationToken cancellationToken)
    {
        if (options.PageHttpOverride != null)
        {
            return await options.PageHttpOverride(url, cancellationToken).ConfigureAwait(false);
        }

        var analysis = new HttpAnalysis
        {
            Subject = url
        };
        await analysis.AnalyzeUrl(
            url,
            checkHsts: false,
            logger: new InternalLogger(),
            collectHeaders: false,
            captureBody: true,
            cancellationToken: cancellationToken,
            requestOptions: options.HttpRequestOptions).ConfigureAwait(false);
        return analysis;
    }

    private static IReadOnlyList<TyposquattingVisualAssetCandidate> FindVisualAssetCandidates(
        string url,
        HttpAnalysis? page,
        TyposquattingVisualSimilarityOptions options)
    {
        var finalUrl = page?.VisitedUrls?.LastOrDefault();
        if (string.IsNullOrWhiteSpace(finalUrl))
        {
            finalUrl = url;
        }

        if (!Uri.TryCreate(finalUrl, UriKind.Absolute, out var baseUri))
        {
            return Array.Empty<TyposquattingVisualAssetCandidate>();
        }

        var body = page?.Body ?? string.Empty;
        var candidates = new List<TyposquattingVisualAssetCandidate>();

        foreach (Match match in LinkTagRegex.Matches(body))
        {
            var tag = match.Value;
            var rel = ExtractAttribute(tag, "rel");
            var href = ExtractAttribute(tag, "href");
            if (string.IsNullOrWhiteSpace(rel) || string.IsNullOrWhiteSpace(href))
            {
                continue;
            }

            var resolved = ResolveAssetUrl(baseUri, href);
            if (string.IsNullOrWhiteSpace(resolved))
            {
                continue;
            }

            var relValue = rel.Trim().ToLowerInvariant();
            if (relValue.Contains("apple-touch-icon", StringComparison.Ordinal))
            {
                candidates.Add(new TyposquattingVisualAssetCandidate(resolved!, TyposquattingVisualArtifactKind.AppleTouchIcon, 10));
                continue;
            }

            if (relValue.Contains("icon", StringComparison.Ordinal))
            {
                candidates.Add(new TyposquattingVisualAssetCandidate(resolved!, TyposquattingVisualArtifactKind.Favicon, 20));
            }
        }

        foreach (Match match in MetaTagRegex.Matches(body))
        {
            var tag = match.Value;
            var property = ExtractAttribute(tag, "property");
            var name = ExtractAttribute(tag, "name");
            var content = ExtractAttribute(tag, "content");
            if (string.IsNullOrWhiteSpace(content))
            {
                continue;
            }

            var resolved = ResolveAssetUrl(baseUri, content);
            if (string.IsNullOrWhiteSpace(resolved))
            {
                continue;
            }

            if (string.Equals(property, "og:image", StringComparison.OrdinalIgnoreCase)
                || string.Equals(name, "twitter:image", StringComparison.OrdinalIgnoreCase)
                || string.Equals(name, "twitter:image:src", StringComparison.OrdinalIgnoreCase))
            {
                var kind = string.Equals(property, "og:image", StringComparison.OrdinalIgnoreCase)
                    ? TyposquattingVisualArtifactKind.OpenGraphImage
                    : TyposquattingVisualArtifactKind.TwitterImage;
                var priority = kind == TyposquattingVisualArtifactKind.OpenGraphImage ? 30 : 40;
                candidates.Add(new TyposquattingVisualAssetCandidate(resolved!, kind, priority));
            }
        }

        candidates.Add(new TyposquattingVisualAssetCandidate(new Uri(baseUri, "/favicon.ico").ToString(), TyposquattingVisualArtifactKind.Favicon, 50));

        return candidates
            .Where(static candidate => !string.IsNullOrWhiteSpace(candidate.Url))
            .GroupBy(static candidate => candidate.Url, StringComparer.OrdinalIgnoreCase)
            .Select(static group => group.OrderBy(candidate => candidate.Priority).First())
            .OrderBy(static candidate => candidate.Priority)
            .ThenBy(static candidate => candidate.Url, StringComparer.OrdinalIgnoreCase)
            .Take(Math.Max(1, options.MaxAssetsPerPage))
            .ToArray();
    }

    private static string ExtractAttribute(string tag, string attributeName)
    {
        if (string.IsNullOrWhiteSpace(tag) || string.IsNullOrWhiteSpace(attributeName))
        {
            return string.Empty;
        }

        var pattern = attributeName + "\\s*=\\s*(?:\"(?<value>[^\"]*)\"|'(?<value>[^']*)'|(?<value>[^\\s>]+))";
        var match = Regex.Match(tag, pattern, RegexOptions.IgnoreCase | RegexOptions.Compiled);
        if (!match.Success)
        {
            return string.Empty;
        }

        return WebUtility.HtmlDecode(match.Groups["value"].Value ?? string.Empty).Trim();
    }

    private static string? ResolveAssetUrl(Uri baseUri, string rawValue)
    {
        if (string.IsNullOrWhiteSpace(rawValue))
        {
            return null;
        }

        var trimmedValue = WebUtility.HtmlDecode(rawValue).Trim();
        if (trimmedValue.StartsWith("//", StringComparison.Ordinal))
        {
            return baseUri.Scheme + ":" + trimmedValue;
        }

        if (Uri.TryCreate(trimmedValue, UriKind.Absolute, out var absoluteUri))
        {
            return absoluteUri.ToString();
        }

        if (Uri.TryCreate(baseUri, trimmedValue, out var relativeUri))
        {
            return relativeUri.ToString();
        }

        return null;
    }

    private static async Task<TyposquattingVisualArtifact?> DownloadAssetAsync(
        TyposquattingVisualAssetCandidate asset,
        TyposquattingVisualSimilarityOptions options,
        CancellationToken cancellationToken)
    {
        if (options.AssetDownloadOverride != null)
        {
            var overriddenArtifact = await options.AssetDownloadOverride(asset.Url, cancellationToken).ConfigureAwait(false);
            if (overriddenArtifact == null)
            {
                return null;
            }

            return ApplyArtifactMetadata(overriddenArtifact, asset);
        }

        if (options.MaxAssetBytes <= 0)
        {
            return null;
        }

        using var handler = new HttpClientHandler
        {
            AllowAutoRedirect = true
        };

        if (options.HttpRequestOptions.DisableTlsValidation)
        {
            handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
        }

        if (!string.IsNullOrWhiteSpace(options.HttpRequestOptions.ProxyUrl))
        {
            handler.UseProxy = true;
            handler.Proxy = new WebProxy(options.HttpRequestOptions.ProxyUrl);
        }

        using var client = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(30)
        };

        using var request = new HttpRequestMessage(HttpMethod.Get, asset.Url);
        foreach (var header in options.HttpRequestOptions.Headers)
        {
            request.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }

        if (!string.IsNullOrWhiteSpace(options.HttpRequestOptions.Cookie))
        {
            request.Headers.TryAddWithoutValidation("Cookie", options.HttpRequestOptions.Cookie);
        }

        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            return null;
        }

        var contentLength = response.Content.Headers.ContentLength;
        if (contentLength.HasValue && contentLength.Value > options.MaxAssetBytes)
        {
            return null;
        }

        var imageBytes = await ReadContentBytesAsync(response.Content, options.MaxAssetBytes, cancellationToken).ConfigureAwait(false);
        if (imageBytes == null || imageBytes.Length == 0)
        {
            return null;
        }

        return new TyposquattingVisualArtifact
        {
            ImageBytes = imageBytes,
            MimeType = response.Content.Headers.ContentType?.MediaType,
            Kind = asset.Kind,
            SourceUrl = asset.Url
        };
    }

    private static TyposquattingVisualArtifact ApplyArtifactMetadata(
        TyposquattingVisualArtifact artifact,
        TyposquattingVisualAssetCandidate asset)
    {
        return new TyposquattingVisualArtifact
        {
            ImageBytes = artifact.ImageBytes,
            MimeType = artifact.MimeType,
            FingerprintHex = artifact.FingerprintHex,
            Width = artifact.Width,
            Height = artifact.Height,
            Kind = artifact.Kind == TyposquattingVisualArtifactKind.Unknown ? asset.Kind : artifact.Kind,
            SourceUrl = string.IsNullOrWhiteSpace(artifact.SourceUrl) ? asset.Url : artifact.SourceUrl
        };
    }

    private static async Task<byte[]?> ReadContentBytesAsync(HttpContent content, int maxBytes, CancellationToken cancellationToken)
    {
#if NET8_0_OR_GREATER
        using var stream = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#else
        using var stream = await content.ReadAsStreamAsync().WaitWithCancellation(cancellationToken).ConfigureAwait(false);
#endif
        using var buffer = new MemoryStream();
        var chunk = new byte[81920];
        while (true)
        {
            var read = await stream.ReadAsync(chunk, 0, chunk.Length, cancellationToken).ConfigureAwait(false);
            if (read <= 0)
            {
                break;
            }

            if (buffer.Length + read > maxBytes)
            {
                return null;
            }

            await buffer.WriteAsync(chunk, 0, read, cancellationToken).ConfigureAwait(false);
        }

        return buffer.ToArray();
    }

    private sealed class TyposquattingVisualAssetCandidate
    {
        internal TyposquattingVisualAssetCandidate(string url, TyposquattingVisualArtifactKind kind, int priority)
        {
            Url = url;
            Kind = kind;
            Priority = priority;
        }

        internal string Url { get; }
        internal TyposquattingVisualArtifactKind Kind { get; }
        internal int Priority { get; }
    }
}

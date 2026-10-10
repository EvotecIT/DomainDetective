using OfficeIMO.Drawing;
using System;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
#if NET8_0_OR_GREATER
using HtmlTinkerX;
using Microsoft.Playwright;
#endif

namespace DomainDetective.Visual;

internal static class DomainDetectiveVisualProvider
{
    public static (string FingerprintHex, int? Width, int? Height)? BuildFingerprint(TyposquattingVisualArtifact artifact)
    {
        if (artifact == null)
        {
            return null;
        }

        if (artifact.ImageBytes == null || artifact.ImageBytes.Length == 0)
        {
            return null;
        }

        if (!OfficeRasterImageDecoder.TryDecode(artifact.ImageBytes, out var image) || image == null)
        {
            return null;
        }

        try
        {
            var hash = OfficeRasterFingerprinting.DifferenceHash(image);
            return (hash.ToString("x16", CultureInfo.InvariantCulture), image.Width, image.Height);
        }
        catch (ArgumentException exception) when (exception.ParamName == "source")
        {
            // A decoded image can still exceed the bounded resampling working set.
            return null;
        }
    }

    public static Task<TyposquattingVisualArtifact?> CaptureBrowserArtifactAsync(
        string url,
        TyposquattingVisualSimilarityOptions options,
        CancellationToken cancellationToken)
    {
#if NET8_0_OR_GREATER
        return CaptureBrowserArtifactCoreAsync(url, options, cancellationToken);
#else
        return Task.FromResult<TyposquattingVisualArtifact?>(null);
#endif
    }

#if NET8_0_OR_GREATER
    private static async Task<TyposquattingVisualArtifact?> CaptureBrowserArtifactCoreAsync(
        string url,
        TyposquattingVisualSimilarityOptions options,
        CancellationToken cancellationToken)
    {
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        linkedCts.CancelAfter(options.BrowserCaptureTimeout);
        try
        {
            await using var session = await HtmlBrowser.OpenSessionAsync(url, new HtmlBrowserLaunchOptions
            {
                Headless = true,
                ViewportWidth = Math.Max(320, options.BrowserViewportWidth),
                ViewportHeight = Math.Max(240, options.BrowserViewportHeight),
                // Typosquatting probes intentionally continue through invalid certificates.
                IgnoreHTTPSErrors = options.HttpRequestOptions.DisableTlsValidation,
                LoadState = HtmlBrowserLoadState.NetworkIdle,
                Timeout = (int)Math.Min(int.MaxValue, options.BrowserCaptureTimeout.TotalMilliseconds)
            }, linkedCts.Token).ConfigureAwait(false);
            var page = session.Page;

            if (options.BrowserPostLoadDelay > TimeSpan.Zero)
            {
                await page.WaitForTimeoutAsync((float)options.BrowserPostLoadDelay.TotalMilliseconds)
                    .WaitAsync(linkedCts.Token)
                    .ConfigureAwait(false);
            }

            var bytes = await page.ScreenshotAsync(new PageScreenshotOptions
            {
                FullPage = options.BrowserFullPageScreenshot,
                Type = ScreenshotType.Png
            }).WaitAsync(linkedCts.Token).ConfigureAwait(false);
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
        catch (PlaywrightException)
        {
            return null;
        }
        catch (OperationCanceledException) when (linkedCts.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            return null;
        }
        catch (TimeoutException)
        {
            return null;
        }
    }
#endif
}

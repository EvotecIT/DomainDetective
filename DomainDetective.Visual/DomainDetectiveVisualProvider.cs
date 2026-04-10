using SixLabors.ImageSharp;
using SixLabors.ImageSharp.Formats;
using SixLabors.ImageSharp.PixelFormats;
using SixLabors.ImageSharp.Processing;
using System;
using System.Threading;
using System.Threading.Tasks;
#if NET8_0_OR_GREATER
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

        try
        {
            using var image = Image.Load<Rgba32>(artifact.ImageBytes);
            var originalWidth = image.Width;
            var originalHeight = image.Height;
            image.Mutate(ctx => ctx.Resize(new ResizeOptions
            {
                Size = new Size(9, 8),
                Mode = ResizeMode.Stretch,
                Sampler = KnownResamplers.Bicubic
            }).Grayscale());

            ulong hash = 0;
            var bit = 0;
            for (var y = 0; y < 8; y++)
            {
                for (var x = 0; x < 8; x++)
                {
                    var left = image[x, y].R;
                    var right = image[x + 1, y].R;
                    if (left > right)
                    {
                        hash |= 1UL << bit;
                    }

                    bit++;
                }
            }

            return (hash.ToString("x16"), originalWidth, originalHeight);
        }
        catch (UnknownImageFormatException)
        {
            return null;
        }
        catch (InvalidImageContentException)
        {
            return null;
        }
        catch (NotSupportedException)
        {
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
            using var playwright = await Playwright.CreateAsync()
                .WaitAsync(linkedCts.Token)
                .ConfigureAwait(false);
            await using var browser = await playwright.Chromium.LaunchAsync(new BrowserTypeLaunchOptions
            {
                Headless = true
            }).WaitAsync(linkedCts.Token).ConfigureAwait(false);
            await using var context = await browser.NewContextAsync(new BrowserNewContextOptions
            {
                ViewportSize = new ViewportSize
                {
                    Width = Math.Max(320, options.BrowserViewportWidth),
                    Height = Math.Max(240, options.BrowserViewportHeight)
                },
                IgnoreHTTPSErrors = options.HttpRequestOptions.DisableTlsValidation
            }).WaitAsync(linkedCts.Token).ConfigureAwait(false);
            var page = await context.NewPageAsync().WaitAsync(linkedCts.Token).ConfigureAwait(false);
            await page.GotoAsync(url, new PageGotoOptions
            {
                WaitUntil = WaitUntilState.NetworkIdle,
                Timeout = (float)options.BrowserCaptureTimeout.TotalMilliseconds
            }).WaitAsync(linkedCts.Token).ConfigureAwait(false);

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

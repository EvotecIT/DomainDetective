using SixLabors.ImageSharp;
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

            return (hash.ToString("x16"), image.Width, image.Height);
        }
        catch
        {
            return null;
        }
    }

    public static async Task<TyposquattingVisualArtifact?> CaptureBrowserArtifactAsync(
        string url,
        TyposquattingVisualSimilarityOptions options,
        CancellationToken cancellationToken)
    {
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
        await Task.CompletedTask.ConfigureAwait(false);
        return null;
#endif
    }
}

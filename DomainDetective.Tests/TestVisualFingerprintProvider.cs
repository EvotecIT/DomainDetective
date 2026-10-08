using System;
using System.Threading.Tasks;
using DomainDetective.Visual;
using OfficeIMO.Drawing;
using Xunit;

namespace DomainDetective.Tests;

public sealed class TestVisualFingerprintProvider {
    [Fact]
    public void EncodedImagesProduceRowMajorDifferenceHashesAndOriginalDimensions() {
        DomainDetectiveVisualRegistration.Register();
        var image = new OfficeRasterImage(9, 8);
        for (int y = 0; y < 8; y++) {
            for (int x = 0; x < 9; x++) {
                byte value = (byte)((x + y) % 2 == 0 ? 220 : 20);
                image.SetPixel(x, y, OfficeColor.FromRgb(value, value, value));
            }
        }
        byte[] bytes = OfficeRasterImageEncoder.Encode(image, OfficeImageExportFormat.Png);

        var fingerprint = DomainDetectiveOptionalFeatures.BuildTyposquattingFingerprint(
            new TyposquattingVisualArtifact { ImageBytes = bytes });

        Assert.NotNull(fingerprint);
        Assert.Equal("aa55aa55aa55aa55", fingerprint!.Value.FingerprintHex);
        Assert.Equal(9, fingerprint.Value.Width);
        Assert.Equal(8, fingerprint.Value.Height);
    }

    [Theory]
    [InlineData(OfficeImageExportFormat.Png)]
    [InlineData(OfficeImageExportFormat.Jpeg)]
    public void ResizingPreservesTheSignalAndReportsSourceDimensions(OfficeImageExportFormat format) {
        DomainDetectiveVisualRegistration.Register();
        var image = new OfficeRasterImage(90, 80);
        for (int y = 0; y < image.Height; y++) {
            for (int x = 0; x < image.Width; x++) {
                byte value = (byte)(250 - x * 2);
                image.SetPixel(x, y, OfficeColor.FromRgb(value, value, value));
            }
        }
        var fingerprint = DomainDetectiveOptionalFeatures.BuildTyposquattingFingerprint(
            new TyposquattingVisualArtifact { ImageBytes = OfficeRasterImageEncoder.Encode(image, format) });

        Assert.NotNull(fingerprint);
        Assert.Equal("ffffffffffffffff", fingerprint!.Value.FingerprintHex);
        Assert.Equal(90, fingerprint.Value.Width);
        Assert.Equal(80, fingerprint.Value.Height);
    }

    [Fact]
    public void InvalidAndOversizedAssetsDoNotProduceVisualSignals() {
        DomainDetectiveVisualRegistration.Register();
        Assert.Null(DomainDetectiveOptionalFeatures.BuildTyposquattingFingerprint(new TyposquattingVisualArtifact()));
        Assert.Null(DomainDetectiveOptionalFeatures.BuildTyposquattingFingerprint(
            new TyposquattingVisualArtifact { ImageBytes = new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 } }));
        byte[] gif = Convert.FromBase64String("R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAkQBADs=");
        gif[6] = 0x10;
        gif[7] = 0x27;
        gif[8] = 0x10;
        gif[9] = 0x27;
        Assert.Null(DomainDetectiveOptionalFeatures.BuildTyposquattingFingerprint(
            new TyposquattingVisualArtifact { ImageBytes = gif }));
    }

    [Fact]
    public void DecodableAssetsOutsideTheResamplingBudgetDoNotAbortAnalysis() {
        DomainDetectiveVisualRegistration.Register();
        // A narrow, highly compressible PNG can fit the download and decoded-pixel limits
        // while its bicubic contribution table exceeds the resampler's working set.
        var image = new OfficeRasterImage(1, 12_000_000, OfficeColor.Red);
        Assert.Throws<ArgumentException>(() => OfficeRasterFingerprinting.DifferenceHash(image));
        byte[] bytes = OfficeRasterImageEncoder.Encode(image, OfficeImageExportFormat.Png);
        Assert.True(bytes.Length < 1024 * 1024);

        Assert.Null(DomainDetectiveOptionalFeatures.BuildTyposquattingFingerprint(
            new TyposquattingVisualArtifact { ImageBytes = bytes }));
    }

    [Fact]
    public async Task ProfileConstructionUsesDecodedBytesAndPreservesPrecomputedOverrides() {
        DomainDetectiveVisualRegistration.Register();
        var bytes = OfficeRasterImageEncoder.Encode(new OfficeRasterImage(3, 2, OfficeColor.Red), OfficeImageExportFormat.Png);
        var options = new TyposquattingVisualSimilarityOptions {
            Enabled = true,
            EnableStaticAssetCapture = false,
            CaptureManyOverride = (_, _) => Task.FromResult<System.Collections.Generic.IReadOnlyList<TyposquattingVisualArtifact>>(
                new[] {
                    new TyposquattingVisualArtifact { ImageBytes = bytes, Kind = TyposquattingVisualArtifactKind.Favicon },
                    new TyposquattingVisualArtifact { FingerprintHex = "123456789abcdef0", Width = 7, Height = 4 }
                })
        };

        var profile = await TyposquattingVisualSimilarityAnalyzer.BuildProfileAsync("example.com", options);

        Assert.NotNull(profile);
        Assert.Equal(2, profile!.Signals.Count);
        Assert.Equal("0000000000000000", profile.Signals[0].FingerprintHex);
        Assert.Equal(3, profile.Signals[0].Width);
        Assert.Equal(2, profile.Signals[0].Height);
        Assert.Equal("123456789abcdef0", profile.Signals[1].FingerprintHex);
    }
}

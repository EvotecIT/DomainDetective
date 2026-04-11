using System;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Registers optional dependency-backed feature providers without changing the main analysis API.
/// </summary>
public static class DomainDetectiveOptionalFeatures
{
    private static volatile Func<string, string, (bool IsVerified, string ClearText)>? _securityTxtPgpVerifier;
    private static volatile VisualProviderRegistration? _visualProvider;
    private static volatile Func<string, CertificateInventoryCaptureOptions, InternalLogger?, CancellationToken, Task<SubdomainDiscoveryEntry?>>? _ctSqlExactMetadataProvider;

    private sealed class VisualProviderRegistration
    {
        public VisualProviderRegistration(
            Func<TyposquattingVisualArtifact, (string FingerprintHex, int? Width, int? Height)?> fingerprintBuilder,
            Func<string, TyposquattingVisualSimilarityOptions, CancellationToken, Task<TyposquattingVisualArtifact?>> browserCapture)
        {
            FingerprintBuilder = fingerprintBuilder;
            BrowserCapture = browserCapture;
        }

        public Func<TyposquattingVisualArtifact, (string FingerprintHex, int? Width, int? Height)?> FingerprintBuilder { get; }

        public Func<string, TyposquattingVisualSimilarityOptions, CancellationToken, Task<TyposquattingVisualArtifact?>> BrowserCapture { get; }
    }

    /// <summary>
    /// Indicates whether an optional PGP verifier has been registered.
    /// </summary>
    public static bool HasPgpVerifier => _securityTxtPgpVerifier != null;

    /// <summary>
    /// Indicates whether optional visual providers have been registered.
    /// </summary>
    public static bool HasVisualProvider => _visualProvider != null;

    /// <summary>
    /// Indicates whether an optional CT SQL exact-metadata provider has been registered.
    /// </summary>
    public static bool HasCtSqlProvider => _ctSqlExactMetadataProvider != null;

    /// <summary>
    /// Registers PGP-backed security.txt clear-signature verification.
    /// </summary>
    public static void RegisterPgpVerifier(Func<string, string, (bool IsVerified, string ClearText)> verifier)
    {
        _securityTxtPgpVerifier = verifier ?? throw new ArgumentNullException(nameof(verifier));
    }

    /// <summary>
    /// Registers visual fingerprinting and browser capture helpers used by typosquatting analysis.
    /// </summary>
    public static void RegisterVisualProvider(
        Func<TyposquattingVisualArtifact, (string FingerprintHex, int? Width, int? Height)?> fingerprintBuilder,
        Func<string, TyposquattingVisualSimilarityOptions, CancellationToken, Task<TyposquattingVisualArtifact?>> browserCapture)
    {
        _visualProvider = new VisualProviderRegistration(
            fingerprintBuilder ?? throw new ArgumentNullException(nameof(fingerprintBuilder)),
            browserCapture ?? throw new ArgumentNullException(nameof(browserCapture)));
    }

    /// <summary>
    /// Registers a caller-supplied exact-host CT metadata provider for the future CtSql package split.
    /// </summary>
    public static void RegisterCtSqlExactMetadataProvider(
        Func<string, CertificateInventoryCaptureOptions, InternalLogger?, CancellationToken, Task<SubdomainDiscoveryEntry?>> provider)
    {
        _ctSqlExactMetadataProvider = provider ?? throw new ArgumentNullException(nameof(provider));
    }

    internal static bool TryVerifySecurityTxtSignature(string signedText, string? publicKey, out bool isVerified, out string clearText)
    {
        isVerified = false;
        clearText = string.Empty;

        var verifier = _securityTxtPgpVerifier;
        if (verifier == null || string.IsNullOrWhiteSpace(publicKey))
        {
            return false;
        }

        var result = verifier(signedText, publicKey!);
        isVerified = result.IsVerified;
        clearText = result.ClearText ?? string.Empty;
        return true;
    }

    internal static (string FingerprintHex, int? Width, int? Height)? BuildTyposquattingFingerprint(TyposquattingVisualArtifact artifact)
    {
        var provider = _visualProvider;
        if (provider == null)
        {
            return null;
        }

        return provider.FingerprintBuilder(artifact);
    }

    internal static Task<TyposquattingVisualArtifact?> CaptureTyposquattingBrowserArtifactAsync(
        string url,
        TyposquattingVisualSimilarityOptions options,
        CancellationToken cancellationToken)
    {
        var provider = _visualProvider;
        if (provider == null)
        {
            return Task.FromResult<TyposquattingVisualArtifact?>(null);
        }

        return provider.BrowserCapture(url, options, cancellationToken);
    }

    internal static Func<string, CertificateInventoryCaptureOptions, InternalLogger?, CancellationToken, Task<SubdomainDiscoveryEntry?>>? GetCtSqlExactMetadataProvider()
    {
        return _ctSqlExactMetadataProvider;
    }
}

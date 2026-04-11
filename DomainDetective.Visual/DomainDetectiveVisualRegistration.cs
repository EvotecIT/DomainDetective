using DomainDetective;

namespace DomainDetective.Visual;

/// <summary>
/// Registers the optional visual providers used by typosquatting analysis.
/// </summary>
public static class DomainDetectiveVisualRegistration
{
    /// <summary>
    /// Registers the DomainDetective.Visual provider pair, replacing any visual provider already registered.
    /// </summary>
    public static void Register()
    {
        DomainDetectiveOptionalFeatures.RegisterVisualProvider(
            DomainDetectiveVisualProvider.BuildFingerprint,
            DomainDetectiveVisualProvider.CaptureBrowserArtifactAsync);
    }
}

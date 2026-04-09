using DomainDetective;

namespace DomainDetective.Visual;

/// <summary>
/// Registers the optional visual providers used by typosquatting analysis.
/// </summary>
public static class DomainDetectiveVisualRegistration
{
    public static void Register()
    {
        DomainDetectiveOptionalFeatures.RegisterVisualProvider(
            DomainDetectiveVisualProvider.BuildFingerprint,
            DomainDetectiveVisualProvider.CaptureBrowserArtifactAsync);
    }
}

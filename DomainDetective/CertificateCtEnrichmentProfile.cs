namespace DomainDetective;

/// <summary>
/// Baseline profile used to configure certificate transparency discovery during inventory capture.
/// </summary>
public enum CertificateCtEnrichmentProfile {
    /// <summary>
    /// Preserve default behavior (crt.sh template enabled) and apply explicit source toggles.
    /// </summary>
    Default = 0,
    /// <summary>
    /// Disable CT discovery for HTTPS probes.
    /// </summary>
    Disabled = 1,
    /// <summary>
    /// Use public CT APIs only (for example crt.sh) unless explicitly overridden by source toggles.
    /// </summary>
    Public = 2,
    /// <summary>
    /// Prefer a broader source set and auto-enable commercial sources when credentials are provided.
    /// </summary>
    Extended = 3
}

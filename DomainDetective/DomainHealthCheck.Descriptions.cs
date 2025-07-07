namespace DomainDetective;

/// <summary>
/// Provides access to descriptions for each health check type.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public partial class DomainHealthCheck {
    /// <summary>Gets the description for a health check.</summary>
    /// <param name="type">Health check type.</param>
    /// <returns>Description instance or <c>null</c>.</returns>
    public static CheckDescription? GetCheckDescription(HealthCheckType type) =>
        CheckDescriptions.Get(type);
}

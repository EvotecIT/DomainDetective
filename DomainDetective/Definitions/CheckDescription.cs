namespace DomainDetective;

/// <summary>
/// Describes a domain health check.
/// </summary>
/// <param name="Summary">Short explanation of the check.</param>
/// <param name="RfcLink">Link to the relevant RFC when available.</param>
/// <param name="Remediation">Suggested remediation steps.</param>
public sealed record CheckDescription(string Summary, string? RfcLink = null, string? Remediation = null);

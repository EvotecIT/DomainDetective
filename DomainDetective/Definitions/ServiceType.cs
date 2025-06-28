namespace DomainDetective;

/// <summary>
/// Enumerates common service ports used in health checks.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public enum ServiceType {
    /// <summary>SMTP service running on port 25.</summary>
    SMTP = 25,
    /// <summary>HTTPS service running on port 443.</summary>
    HTTPS = 443
}
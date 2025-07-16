namespace DomainDetective;

/// <summary>
/// Predefined service port profiles for port scanning.
/// </summary>
public enum PortScanProfile
{
    /// <summary>Standard scan of top ports.</summary>
    Default,
    /// <summary>Ports commonly used by SMB.</summary>
    SMB,
    /// <summary>Ports commonly used by NTP.</summary>
    NTP
}

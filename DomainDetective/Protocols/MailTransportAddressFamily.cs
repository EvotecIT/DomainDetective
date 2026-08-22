namespace DomainDetective;

/// <summary>
/// Selects the network address family used by a mail transport probe.
/// </summary>
public enum MailTransportAddressFamily {
    /// <summary>Allows the operating system to select IPv4 or IPv6.</summary>
    Any,

    /// <summary>Uses IPv4 addresses only.</summary>
    IPv4,

    /// <summary>Uses IPv6 addresses only.</summary>
    IPv6
}

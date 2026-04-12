namespace DomainDetective;

/// <summary>
/// Normalized failure kind used for certificate capture, persistence, and reuse decisions.
/// </summary>
public enum CertificateFailureKind {
    /// <summary>Represents the none value.</summary>
    None,
    /// <summary>Represents the unknown value.</summary>
    Unknown,
    /// <summary>Represents the cancelled value.</summary>
    Cancelled,
    /// <summary>Represents the timeout value.</summary>
    Timeout,
    /// <summary>Represents the tls handshake value.</summary>
    TlsHandshake,
    /// <summary>Represents the name resolution value.</summary>
    NameResolution,
    /// <summary>Represents the connection refused value.</summary>
    ConnectionRefused,
    /// <summary>Represents the connection reset value.</summary>
    ConnectionReset,
    /// <summary>Represents the connection aborted value.</summary>
    ConnectionAborted,
    /// <summary>Represents the network unreachable value.</summary>
    NetworkUnreachable,
    /// <summary>Represents the connection error value.</summary>
    ConnectionError
}

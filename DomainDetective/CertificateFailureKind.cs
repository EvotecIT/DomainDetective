namespace DomainDetective;

/// <summary>
/// Normalized failure kind used for certificate capture, persistence, and reuse decisions.
/// </summary>
public enum CertificateFailureKind {
    None,
    Unknown,
    Cancelled,
    Timeout,
    TlsHandshake,
    NameResolution,
    ConnectionRefused,
    ConnectionReset,
    ConnectionAborted,
    NetworkUnreachable,
    ConnectionError
}

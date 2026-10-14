namespace DomainDetective;

/// <summary>Distinguishes transport observations from missing DoT evidence.</summary>
public enum DnsOverTlsProbeOutcome {
    /// <summary>The probe did not establish an outcome.</summary>
    Unknown,
    /// <summary>A correlated DNS response was received over TLS.</summary>
    Supported,
    /// <summary>The TCP connection was explicitly refused.</summary>
    ConnectionRefused,
    /// <summary>The probe deadline expired.</summary>
    TimedOut,
    /// <summary>The overall check budget prevented completion.</summary>
    BudgetExhausted,
    /// <summary>The TLS handshake failed after connecting.</summary>
    HandshakeFailed,
    /// <summary>The peer completed TLS but no valid DNS exchange was established.</summary>
    DnsExchangeFailed,
    /// <summary>A different connection or probe error occurred.</summary>
    Failed
}

/// <summary>Records DoT evidence and the stage at which a probe stopped.</summary>
public sealed record DnsOverTlsEndpointResult {
    /// <summary>Gets the nameserver hostname.</summary>
    public string NameServerHost { get; init; } = string.Empty;
    /// <summary>Gets the target address.</summary>
    public string ServerIp { get; init; } = string.Empty;
    /// <summary>Gets the target port.</summary>
    public int Port { get; init; }
    /// <summary>True when DNS-over-TLS support was established by the probe.</summary>
    public bool Supported { get; init; }
    /// <summary>Gets the structured outcome.</summary>
    public DnsOverTlsProbeOutcome Outcome { get; init; }
    /// <summary>True when the probe entered its transport rather than being skipped by the budget.</summary>
    public bool Attempted { get; init; }
    /// <summary>True when a TLS handshake completed, even if the DNS exchange failed.</summary>
    public bool TlsHandshakeSucceeded { get; init; }
    /// <summary>True when a correlated DNS response was received over TLS.</summary>
    public bool DnsExchangeVerified { get; init; }
    /// <summary>Gets the failure stage: connect, TLS handshake, DNS exchange, or budget.</summary>
    public string? FailureStage { get; init; }
    /// <summary>Gets elapsed time including transport cleanup.</summary>
    public long ElapsedMilliseconds { get; init; }
    /// <summary>Gets the negotiated protocol.</summary>
    public string? Protocol { get; init; }
    /// <summary>Gets the negotiated cipher suite.</summary>
    public string? CipherSuite { get; init; }
    /// <summary>Gets certificate hostname validation evidence.</summary>
    public bool? HostnameMatch { get; init; }
    /// <summary>Gets certificate validation evidence.</summary>
    public bool? CertificateValid { get; init; }
    /// <summary>Gets the failure diagnostic.</summary>
    public string? Error { get; init; }
}

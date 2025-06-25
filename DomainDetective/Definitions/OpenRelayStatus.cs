namespace DomainDetective;

/// <summary>
/// Describes the outcome of an SMTP relay test.
/// </summary>
public enum OpenRelayStatus {
    /// <summary>The status has not been determined.</summary>
    Unknown,
    /// <summary>The server allowed relaying.</summary>
    AllowsRelay,
    /// <summary>The server denied relaying.</summary>
    Denied,
    /// <summary>The test failed due to connection issues.</summary>
    ConnectionFailed
}

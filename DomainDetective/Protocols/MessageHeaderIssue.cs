namespace DomainDetective;

/// <summary>
/// Identifies issues detected during message header analysis.
/// </summary>
public enum MessageHeaderIssue {
    /// <summary>No ARC headers were found.</summary>
    MissingArc,
    /// <summary>The ARC chain exists but failed validation.</summary>
    InvalidArc,
    /// <summary>One or more DKIM signatures were invalid.</summary>
    InvalidDkim,
    /// <summary>The message appears to have entered Exchange Online directly.</summary>
    DirectToExchangeOnline,
    /// <summary>The message was delivered to Inbox despite failed authentication.</summary>
    AuthenticationFailedDeliveredToInbox,
    /// <summary>The message appears to be same-domain self-spoofing and reached Inbox.</summary>
    SelfSpoofDeliveredToInbox,
    /// <summary>The message appears to have looped between Exchange Online and a third-party gateway.</summary>
    GatewayLoopDetected,
    /// <summary>The expected public MX path was not observed while direct Exchange Online ingress was observed.</summary>
    ExpectedMxBypassed
}

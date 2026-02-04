namespace DomainDetective;

/// <summary>Reachability confidence for a mailbox.</summary>
public enum EmailReachabilityStatus {
    Unknown,
    Safe,
    Risky,
    Invalid
}

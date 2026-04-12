namespace DomainDetective;

/// <summary>Reachability confidence for a mailbox.</summary>
public enum EmailReachabilityStatus {
    /// <summary>Represents the unknown value.</summary>
    Unknown,
    /// <summary>Represents the safe value.</summary>
    Safe,
    /// <summary>Represents the risky value.</summary>
    Risky,
    /// <summary>Represents the invalid value.</summary>
    Invalid
}

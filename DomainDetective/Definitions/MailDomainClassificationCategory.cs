using System.ComponentModel;

namespace DomainDetective.Definitions;

/// <summary>Represents the operational email role of a domain.</summary>
public enum MailDomainClassificationCategory {
    /// <summary>Configured for both inbound and outbound email.</summary>
    [Description("Configured for both inbound and outbound email")] SendingAndReceiving,
    /// <summary>Accepts inbound email but no authorized senders detected.</summary>
    [Description("Accepts inbound email but no authorized senders detected")] ReceivingOnly,
    /// <summary>Authorizes outbound email but does not accept inbound mail.</summary>
    [Description("Authorizes outbound email but does not accept inbound mail")] SendingOnly,
    /// <summary>Domain explicitly rejects mail and authorizes no sending.</summary>
    [Description("Domain explicitly rejects mail and authorizes no sending")] Parked,
    /// <summary>Insufficient data for confident classification.</summary>
    [Description("Insufficient data for confident classification")] Unknown
}


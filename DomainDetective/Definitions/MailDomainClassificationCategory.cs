using System.ComponentModel;

namespace DomainDetective.Definitions;

/// <summary>Represents the operational email role of a domain.</summary>
public enum MailDomainClassificationCategory {
    /// <summary>Configured for both inbound and outbound email.</summary>
    /// <example>Standard corporate domains, typical business email setups</example>
    [Description("Configured for both inbound and outbound email")] SendingAndReceiving,
    /// <summary>Accepts inbound email but no authorized senders detected.</summary>
    /// <example>Support-only or intake mailboxes without outbound sending</example>
    [Description("Accepts inbound email but no authorized senders detected")] ReceivingOnly,
    /// <summary>Authorizes outbound email but does not accept inbound mail.</summary>
    /// <example>Transactional email services, no-reply domains</example>
    [Description("Authorizes outbound email but does not accept inbound mail")] SendingOnly,
    /// <summary>Domain explicitly rejects mail and authorizes no sending.</summary>
    /// <example>Parked or branded web-only properties not intended for email</example>
    [Description("Domain explicitly rejects mail and authorizes no sending")] Parked,
    /// <summary>Insufficient data for confident classification.</summary>
    /// <example>Newly registered domains or DNS/WHOIS unavailable</example>
    [Description("Insufficient data for confident classification")] Unknown
}

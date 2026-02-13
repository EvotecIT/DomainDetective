using System;
using DomainDetective.Providers.Email;

namespace DomainDetective;

/// <summary>SMTP policy overrides for a detected mail provider.</summary>
public sealed class EmailSmtpProviderPolicy {
    /// <summary>Provider to which this policy applies.</summary>
    public MailProviderKind Provider { get; set; }

    /// <summary>True to disable catch-all probing for this provider.</summary>
    public bool DisableCatchAll { get; set; }

    /// <summary>Optional SMTP timeout override.</summary>
    public TimeSpan? SmtpTimeoutOverride { get; set; }

    /// <summary>Optional SMTP port override.</summary>
    public int? SmtpPortOverride { get; set; }
}

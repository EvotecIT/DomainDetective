using System.Collections.Generic;
using DomainDetective.Providers.Email;

namespace DomainDetective;

/// <summary>Miscellaneous mailbox classification details.</summary>
public sealed class EmailAddressMiscDetails {
    /// <summary>True when domain is disposable.</summary>
    public bool IsDisposable { get; set; }

    /// <summary>True when local part is a role account.</summary>
    public bool IsRoleAccount { get; set; }

    /// <summary>True when domain is a consumer/free provider.</summary>
    public bool IsFreeProvider { get; set; }

    /// <summary>True when mailbox is likely B2C.</summary>
    public bool IsB2C { get; set; }

    /// <summary>Resolved Gravatar URL if present.</summary>
    public string? GravatarUrl { get; set; }

    /// <summary>Have I Been Pwned breach indicator.</summary>
    public bool? HaveIBeenPwned { get; set; }

    /// <summary>Detected provider kind based on MX hosts.</summary>
    public MailProviderKind ProviderKind { get; set; } = MailProviderKind.Unknown;

    /// <summary>Provider detection score.</summary>
    public int ProviderScore { get; set; }

    /// <summary>Evidence used for provider detection.</summary>
    public List<string> ProviderEvidence { get; set; } = new();
}

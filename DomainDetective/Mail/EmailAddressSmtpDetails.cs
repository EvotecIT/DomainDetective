using System;
using System.Collections.Generic;

namespace DomainDetective;

/// <summary>SMTP probe details for a mailbox.</summary>
public sealed class EmailAddressSmtpDetails {
    /// <summary>True when SMTP probe was attempted.</summary>
    public bool Checked { get; set; }

    /// <summary>True when connection to SMTP server succeeded.</summary>
    public bool CanConnectSmtp { get; set; }

    /// <summary>True when SMTP server accepted RCPT TO.</summary>
    public bool IsDeliverable { get; set; }

    /// <summary>True when the domain appears to be catch-all.</summary>
    public bool IsCatchAll { get; set; }

    /// <summary>True when SMTP response indicates a full inbox.</summary>
    public bool HasFullInbox { get; set; }

    /// <summary>True when SMTP response indicates a disabled mailbox.</summary>
    public bool IsDisabled { get; set; }

    /// <summary>True when server required STARTTLS for verification.</summary>
    public bool RequiresStartTls { get; set; }

    /// <summary>SMTP host used for probe.</summary>
    public string? Host { get; set; }

    /// <summary>SMTP port used for probe.</summary>
    public int Port { get; set; }

    /// <summary>True when SMTP probe used a proxy.</summary>
    public bool UsedProxy { get; set; }

    /// <summary>Proxy host used for SMTP probing.</summary>
    public string? ProxyHost { get; set; }

    /// <summary>Proxy port used for SMTP probing.</summary>
    public int? ProxyPort { get; set; }

    /// <summary>Verification method used for this result.</summary>
    public string? VerificationMethod { get; set; }

    /// <summary>Optional detail about the verification method.</summary>
    public string? VerificationDetail { get; set; }

    /// <summary>True when a provider web check was used.</summary>
    public bool UsedProviderWebCheck { get; set; }

    /// <summary>SMTP hosts attempted during probing.</summary>
    public List<string> AttemptedHosts { get; set; } = new();

    /// <summary>Errors captured per attempted host.</summary>
    public Dictionary<string, string> AttemptErrors { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Response line for MAIL FROM.</summary>
    public string? MailFromResponse { get; set; }

    /// <summary>Status code parsed from MAIL FROM response.</summary>
    public int? MailFromStatusCode { get; set; }

    /// <summary>Response line for RCPT TO.</summary>
    public string? RcptToResponse { get; set; }

    /// <summary>Status code parsed from RCPT TO response.</summary>
    public int? RcptToStatusCode { get; set; }

    /// <summary>True when SMTP response indicates a temporary failure.</summary>
    public bool IsTemporaryFailure { get; set; }

    /// <summary>True when SMTP response indicates a permanent failure.</summary>
    public bool IsPermanentFailure { get; set; }

    /// <summary>True when SMTP response suggests greylisting.</summary>
    public bool IsGreylisted { get; set; }

    /// <summary>Response line for catch-all RCPT.</summary>
    public string? CatchAllResponse { get; set; }

    /// <summary>Optional error detail.</summary>
    public string? Error { get; set; }
}

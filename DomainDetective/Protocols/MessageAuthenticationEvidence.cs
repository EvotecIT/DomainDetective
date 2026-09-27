using System;
using System.Collections.Generic;

namespace DomainDetective;

/// <summary>Attribution of a header claim, independent of cryptographic verification.</summary>
public enum MessageAuthenticationTrust {
    /// <summary>No authentication header was available.</summary>
    None,
    /// <summary>The header omits the authentication service identifier.</summary>
    Absent,
    /// <summary>The identifier is not attributed to a configured gateway.</summary>
    Unverified,
    /// <summary>The identifier matches a route host; this is plausibility, not proof.</summary>
    RouteMatched,
    /// <summary>The caller explicitly trusts this exact identifier and gateway sanitization.</summary>
    Configured
}

/// <summary>One receiver-reported authentication method and its associated identities.</summary>
public sealed class MessageAuthenticationMethod {
    /// <summary>Method name, such as spf, dkim, dmarc, arc, or compauth.</summary>
    public string Method { get; internal set; } = string.Empty;
    /// <summary>Result token only; never a cryptographic verdict produced by this parser.</summary>
    public string Result { get; internal set; } = string.Empty;
    /// <summary>Identity and reason properties associated with this method.</summary>
    public Dictionary<string, string> Properties { get; } = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Repeated property names; their values cannot establish a unique identity.</summary>
    public List<string> DuplicateProperties { get; } = new();
    /// <summary>Original method clause.</summary>
    public string Raw { get; internal set; } = string.Empty;
}

/// <summary>A single authentication header with preserved origin and method results.</summary>
public sealed class MessageAuthenticationEvidence {
    /// <summary>Authentication service identifier, if supplied.</summary>
    public string? AuthServId { get; internal set; }
    /// <summary>Whether repeated writer properties prevent attributing this observation.</summary>
    public bool AmbiguousAuthServId { get; internal set; }
    /// <summary>Header field name, including original or ARC variants.</summary>
    public string HeaderName { get; internal set; } = string.Empty;
    /// <summary>Original order amongst authentication headers, newest first.</summary>
    public int HeaderIndex { get; internal set; }
    /// <summary>Attribution classification; no header alone proves its writer.</summary>
    public MessageAuthenticationTrust Trust { get; internal set; }
    /// <summary>Receiver-reported methods, preserving multiple signatures.</summary>
    public List<MessageAuthenticationMethod> Methods { get; } = new();
    /// <summary>Original header value.</summary>
    public string Raw { get; internal set; } = string.Empty;
}

/// <summary>Offline header analysis settings. Network verification is a separate operation.</summary>
public sealed class MessageHeaderAnalysisOptions {
    /// <summary>Exact trusted authserv identifiers. The gateway must strip incoming claims of its own identity.</summary>
    public string[] TrustedAuthServIds { get; set; } = Array.Empty<string>();
    /// <summary>Maximum message header characters accepted for parsing.</summary>
    public int MaximumHeaderCharacters { get; set; } = 2 * 1024 * 1024;
    /// <summary>Maximum Received fields evaluated; omitted fields are reported explicitly.</summary>
    public int MaximumReceivedHops { get; set; } = 200;
}

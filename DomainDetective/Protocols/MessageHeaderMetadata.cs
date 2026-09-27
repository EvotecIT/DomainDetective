using System;
using System.Collections.Generic;

namespace DomainDetective;

/// <summary>One original header field; repeatable fields remain separate.</summary>
public sealed class MessageHeaderField {
    /// <summary>Header field name.</summary>
    public string Name { get; internal set; } = string.Empty;
    /// <summary>Original field value.</summary>
    public string Value { get; internal set; } = string.Empty;
}

/// <summary>Parsed mailbox identity, independent of authentication.</summary>
public sealed class MessageMailbox {
    /// <summary>Decoded display name.</summary>
    public string Name { get; internal set; } = string.Empty;
    /// <summary>Mailbox address.</summary>
    public string Address { get; internal set; } = string.Empty;
    /// <summary>Address domain.</summary>
    public string Domain { get; internal set; } = string.Empty;
}

/// <summary>DKIM signature metadata; it is not cryptographic verification.</summary>
public sealed class MessageDkimSignature {
    /// <summary>Original header value.</summary>
    public string Raw { get; internal set; } = string.Empty;
    /// <summary>Signature tags as supplied.</summary>
    public Dictionary<string, string> Tags { get; internal set; } = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Signing domain.</summary>
    public string? Domain { get; internal set; }
    /// <summary>DNS key selector.</summary>
    public string? Selector { get; internal set; }
    /// <summary>Signing algorithm.</summary>
    public string? Algorithm { get; internal set; }
    /// <summary>Header and body canonicalization.</summary>
    public string? Canonicalization { get; internal set; }
    /// <summary>Signed header field names.</summary>
    public string[] SignedHeaders { get; internal set; } = Array.Empty<string>();
    /// <summary>Signature creation time, if representable.</summary>
    public DateTimeOffset? Timestamp { get; internal set; }
    /// <summary>Signature expiry time, if representable.</summary>
    public DateTimeOffset? Expires { get; internal set; }
    /// <summary>Signed body length limit, if supplied.</summary>
    public long? BodyLength { get; internal set; }
    /// <summary>Matching receiver-reported result for this domain and selector.</summary>
    public string? ReceiverResult { get; internal set; }
}

/// <summary>An evidence-based header finding with a stable machine-readable code.</summary>
public sealed class MessageHeaderFinding {
    /// <summary>Finding code.</summary>
    public string Code { get; internal set; } = string.Empty;
    /// <summary>Severity; unusual metadata alone does not establish malicious intent.</summary>
    public AssessmentSeverity Severity { get; internal set; }
    /// <summary>Explanation including the evidence limitation.</summary>
    public string Message { get; internal set; } = string.Empty;
}

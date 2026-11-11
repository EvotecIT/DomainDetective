using System;
using System.Collections.Generic;

namespace DomainDetective;

/// <summary>Full-message signature verification policy. DNS access requires explicit opt-in.</summary>
public sealed class MessageVerificationOptions {
    /// <summary>Header parsing and provenance settings.</summary>
    public MessageHeaderAnalysisOptions HeaderOptions { get; set; } = new();
    /// <summary>Allow DNS TXT public-key retrieval through DomainDetective's configured resolver.</summary>
    public bool AllowDnsLookups { get; set; }
    /// <summary>Offline public-key TXT records keyed by selector._domainkey.domain, compared case-insensitively.</summary>
    public Dictionary<string, string> PublicKeyRecords { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Maximum MIME message size accepted for verification.</summary>
    public int MaximumMessageBytes { get; set; } = 25 * 1024 * 1024;
    /// <summary>Maximum DKIM signatures verified. Additional signatures are reported as not performed.</summary>
    public int MaximumDkimSignatures { get; set; } = 50;
    /// <summary>Maximum distinct DNS public-key queries per operation.</summary>
    public int MaximumDnsQueries { get; set; } = 50;
    /// <summary>Maximum MIME compliance findings retained per message, including all MIME parts.</summary>
    public int MaximumMimeComplianceIssues { get; set; } = 100;
    /// <summary>Maximum raw bytes buffered for a single MIME header.</summary>
    public int MaximumMimeHeaderBytes { get; set; } = 16 * 1024;
    /// <summary>Overall verification timeout, including key acquisition.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);
}

/// <summary>Cryptographic verification outcome, distinct from header claims.</summary>
public enum MessageSignatureStatus {
    /// <summary>Verification was not attempted or required evidence was missing.</summary>
    NotPerformed,
    /// <summary>The supplied message verifies using the retrieved or supplied public key.</summary>
    Valid,
    /// <summary>Verification performed and did not validate the supplied message.</summary>
    Invalid,
    /// <summary>Key acquisition, parsing, or supported-algorithm limitations prevented a conclusion.</summary>
    Inconclusive
}

/// <summary>Cryptographic result for a message signature or ARC chain.</summary>
public sealed class MessageSignatureVerification {
    /// <summary>DKIM or ARC.</summary>
    public string Method { get; internal set; } = string.Empty;
    /// <summary>Signing domain, where applicable.</summary>
    public string? Domain { get; internal set; }
    /// <summary>Key selector, where applicable.</summary>
    public string? Selector { get; internal set; }
    /// <summary>Cryptographic outcome.</summary>
    public MessageSignatureStatus Status { get; internal set; }
    /// <summary>Reason and applicable evidence boundary.</summary>
    public string Explanation { get; internal set; } = string.Empty;
    /// <summary>Whether this verification used DNS-acquired keys.</summary>
    public bool UsedDns { get; internal set; }
    /// <summary>Detailed protocol outcome such as Pass, Fail, Policy, TempError or PermError.</summary>
    public string? ProtocolStatus { get; internal set; }
    /// <summary>Verifier diagnostic, distinct from the higher-level evidence explanation.</summary>
    public string? FailureReason { get; internal set; }
    /// <summary>Additional DomainDetective key-policy failure, separate from the cryptographic protocol result.</summary>
    public string? PolicyFailure { get; internal set; }
    /// <summary>ARC structural and validation error flags, including temporary DNS failures.</summary>
    public string? ArcChainErrors { get; internal set; }
    /// <summary>Individual ARC message-signature and seal results, without exception objects.</summary>
    public IReadOnlyList<MessageArcHeaderVerification> ArcHeaders { get; internal set; } = Array.Empty<MessageArcHeaderVerification>();
}

/// <summary>One verified ARC header's protocol evidence.</summary>
public sealed class MessageArcHeaderVerification {
    /// <summary>ARC-Message-Signature or ARC-Seal.</summary>
    public string Header { get; internal set; } = string.Empty;
    /// <summary>ARC instance number as supplied by the header.</summary>
    public string? Instance { get; internal set; }
    /// <summary>Detailed MimeKit protocol status.</summary>
    public string ProtocolStatus { get; internal set; } = string.Empty;
    /// <summary>Verifier diagnostic for this header.</summary>
    public string? FailureReason { get; internal set; }
}

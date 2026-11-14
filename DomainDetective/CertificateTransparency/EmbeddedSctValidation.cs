using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective;

/// <summary>Outcome of checking one SCT signature against its CT log key.</summary>
public enum SctSignatureStatus {
    /// <summary>The issuer certificate or the log key was unavailable, so the signature was not checked.</summary>
    Unverified = 0,
    /// <summary>The log key verifies the SCT over the reconstructed precertificate entry.</summary>
    Valid = 1,
    /// <summary>The signature does not verify, or uses an algorithm RFC 6962 does not allow.</summary>
    Invalid = 2
}

/// <summary>Whether embedded SCTs satisfy a browser CT policy.</summary>
public enum CtPolicyCompliance {
    /// <summary>Compliance could not be decided, for example because the log list or issuer was unavailable.</summary>
    Undetermined = 0,
    /// <summary>The embedded SCTs satisfy the policy.</summary>
    Compliant = 1,
    /// <summary>The embedded SCTs do not satisfy the policy.</summary>
    NotCompliant = 2
}

/// <summary>Result of evaluating embedded SCTs against one browser CT policy.</summary>
public sealed class CtPolicyEvaluation {
    /// <summary>Policy outcome.</summary>
    public CtPolicyCompliance Compliance { get; init; }
    /// <summary>Short explanation of the outcome.</summary>
    public string Reason { get; init; } = string.Empty;
}

/// <summary>One Signed Certificate Timestamp embedded in a certificate.</summary>
public sealed class EmbeddedSct {
    /// <summary>Base64 SHA-256 log ID.</summary>
    public string LogId { get; init; } = string.Empty;
    /// <summary>Time the log issued the SCT.</summary>
    public DateTimeOffset Timestamp { get; init; }
    /// <summary>True when the log ID appears in the Chrome or Apple log list.</summary>
    public bool LogKnown { get; init; }
    /// <summary>Log description from the log list.</summary>
    public string? LogDescription { get; init; }
    /// <summary>Log operator from the log list.</summary>
    public string? LogOperator { get; init; }
    /// <summary>Log state in Chrome's log list, or null when Chrome does not list the log.</summary>
    public string? ChromeLogState { get; init; }
    /// <summary>Log state in Apple's log list, or null when Apple does not list the log.</summary>
    public string? AppleLogState { get; init; }
    /// <summary>Signature check outcome.</summary>
    public SctSignatureStatus SignatureStatus { get; init; }
}

/// <summary>
/// Embedded SCT list (OID 1.3.6.1.4.1.11129.2.4.2) parsing, signature verification and browser CT policy results.
/// SCTs delivered through the TLS extension or stapled OCSP responses are not observed, so non-compliance
/// covers the embedded path only.
/// </summary>
public sealed class EmbeddedSctValidation {
    /// <summary>Parsed embedded SCTs.</summary>
    public IReadOnlyList<EmbeddedSct> Scts { get; init; } = Array.Empty<EmbeddedSct>();
    /// <summary>Number of SCTs whose signature verified.</summary>
    public int ValidCount => Scts.Count(static sct => sct.SignatureStatus == SctSignatureStatus.Valid);
    /// <summary>Why the SCT list extension was rejected, or null when it parsed.</summary>
    public string? ParseError { get; init; }
    /// <summary>Chrome CT policy result for embedded SCTs.</summary>
    public CtPolicyEvaluation Chrome { get; init; } = new();
    /// <summary>Apple CT policy result for embedded SCTs.</summary>
    public CtPolicyEvaluation Apple { get; init; } = new();
}

using MimeKit;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;

namespace DomainDetective;

/// <summary>DMARC forensic report details.</summary>
public sealed class DmarcForensicReport {
    /// <summary>IP address of the sending host.</summary>
    public string SourceIp { get; set; } = string.Empty;
    /// <summary>Envelope from address.</summary>
    public string OriginalMailFrom { get; set; } = string.Empty;
    /// <summary>Original recipient address.</summary>
    public string? OriginalRcptTo { get; set; }
    /// <summary>Domain from the From header.</summary>
    public string? HeaderFrom { get; set; }
    /// <summary>Arrival date of the message.</summary>
    public DateTimeOffset? ArrivalDate { get; set; }
    /// <summary>Whether the MIME input contained a machine-readable feedback report.</summary>
    public bool HasFeedbackReport { get; set; }
    /// <summary>Feedback-Type declared by the reporter.</summary>
    public string? FeedbackType { get; set; }
    /// <summary>Auth-Failure declared by the reporter, normally dmarc for RFC 9991.</summary>
    public string? AuthFailure { get; set; }
    /// <summary>Mechanisms in the reported Identity-Alignment field.</summary>
    public List<string> IdentityAlignment { get; } = new();
    /// <summary>Reported Delivery-Result, when supplied.</summary>
    public string? DeliveryResult { get; set; }
    /// <summary>First reported DKIM-Domain; all repeated values remain in <see cref="FeedbackFields"/>.</summary>
    public string? DkimDomain { get; set; }
    /// <summary>First reported DKIM-Identity.</summary>
    public string? DkimIdentity { get; set; }
    /// <summary>First reported DKIM-Selector.</summary>
    public string? DkimSelector { get; set; }
    /// <summary>Reported SPF DNS evidence, without local policy evaluation.</summary>
    public string? SpfDns { get; set; }
    /// <summary>Unfolded machine feedback fields, including repeats and extensions.</summary>
    public Dictionary<string, List<string>> FeedbackFields { get; } = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>RFC 9991 field diagnostics; legacy partial reports remain readable.</summary>
    public List<string> ValidationMessages { get; } = new();
}

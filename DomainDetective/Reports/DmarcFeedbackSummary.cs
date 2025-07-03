namespace DomainDetective.Reports;

/// <summary>Summarized DMARC feedback statistics for a domain.</summary>
public sealed class DmarcFeedbackSummary {
    /// <summary>Domain name the statistics apply to.</summary>
    public string Domain { get; set; } = string.Empty;

    /// <summary>Messages passing DMARC evaluation.</summary>
    public int PassCount { get; set; }

    /// <summary>Messages failing DMARC evaluation.</summary>
    public int FailCount { get; set; }

    /// <summary>Total messages seen for the domain.</summary>
    public int TotalCount => PassCount + FailCount;
}

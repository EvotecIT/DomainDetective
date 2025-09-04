namespace DomainDetective;

internal static class DmarcCodes {
    public const string AlignmentMismatch = "DMARC.Alignment.Mismatch";
    public const string AlignmentInvalid = "DMARC.Alignment.Invalid";
    public const string TagDeprecated = "DMARC.Tag.Deprecated";
    public const string UriInvalid = "DMARC.URI.Invalid";
    public const string UriMissingScheme = "DMARC.URI.MissingScheme";
    public const string UriInsecure = "DMARC.URI.Insecure";
    public const string RufTooLarge = "DMARC.RUF.TooLarge";
    public const string ReportingIntervalInvalid = "DMARC.ReportingInterval.Invalid";
    public const string ReportingIntervalZeroOrNegative = "DMARC.ReportingInterval.ZeroOrNegative";
    public const string MissingRecord = "DMARC.Record.Missing";
    public const string MultipleRecords = "DMARC.Record.Multiple";
    public const string StartsInvalid = "DMARC.Record.StartsInvalid";
    public const string RecordLengthExceeds = "DMARC.Record.LengthExceeds";
    public const string QueryFailed = "DMARC.Query.Failed";

    // Positive/posture signals
    /// <summary>DMARC record exists for the domain.</summary>
    public const string Present = "DMARC.Record.Present";

    /// <summary>DMARC record begins with the required v=DMARC1 tag.</summary>
    public const string StartsV1 = "DMARC.Record.StartsV1";

    /// <summary>DMARC policy is set to reject.</summary>
    public const string PolicyReject = "DMARC.Policy.Reject";

    /// <summary>DMARC policy is set to quarantine.</summary>
    public const string PolicyQuarantine = "DMARC.Policy.Quarantine";

    /// <summary>Aggregate reporting address (rua) is configured.</summary>
    public const string RuaPresent = "DMARC.RUA.Present";

    /// <summary>Forensic reporting address (ruf) is configured.</summary>
    public const string RufPresent = "DMARC.RUF.Present";

    /// <summary>Strict DKIM alignment (adkim=s) is enforced.</summary>
    public const string AlignmentStrictDkim = "DMARC.Alignment.DKIM.Strict";

    /// <summary>Strict SPF alignment (aspf=s) is enforced.</summary>
    public const string AlignmentStrictSpf = "DMARC.Alignment.SPF.Strict";

    /// <summary>DMARC policy applies to 100% of mail (pct=100).</summary>
    public const string Percent100 = "DMARC.Percent.100";
}

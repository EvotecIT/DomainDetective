namespace DomainDetective;

internal static class DmarcCodes {
    public const string AlignmentMismatch = "DMARC.Alignment.Mismatch";
    /// <summary>A report address outside the domain whose owner does not authorise receiving its reports.</summary>
    public const string ExternalReportUnauthorized = "DMARC.Report.ExternalUnauthorized";
    /// <summary>A report address outside the domain whose owner authorises receiving its reports.</summary>
    public const string ExternalReportAuthorized = "DMARC.Report.ExternalAuthorized";
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
    public const string ReportingQueryFailed = "DMARC.Reporting.QueryFailed";

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

    /// <summary>A legacy percentage tag pct=100 is published.</summary>
    public const string Percent100 = "DMARC.Percent.100";
    public const string ProviderEnforcementRecommended = "DMARC.Provider.EnforcementRecommended";
    public const string SubdomainPolicyRecommended = "DMARC.SubdomainPolicy.Recommended";
}

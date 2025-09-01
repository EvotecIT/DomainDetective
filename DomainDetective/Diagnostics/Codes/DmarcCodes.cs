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
}

namespace DomainDetective;

internal static class SpfCodes {
    public const string TxtChunkTooLong = "SPF.TxtChunk.TooLong";
    public const string LookupsExceeded = "SPF.Lookups.Exceeded";
    public const string MacroPercentInvalid = "SPF.Macro.PercentInvalid";
    public const string MacroSyntaxInvalid = "SPF.Macro.SyntaxInvalid";
    public const string FlattenedLengthExceeds512 = "SPF.Flattened.LengthExceeds512";
    public const string FlattenedLengthExceeds255 = "SPF.Flattened.LengthExceeds255";
    public const string IncludeCycle = "SPF.Include.Cycle";
    public const string MissingRecord = "SPF.Record.Missing";
    public const string MultipleRecords = "SPF.Record.Multiple";
    public const string StartsInvalid = "SPF.Record.StartsInvalid";
    public const string RecordLengthExceeds = "SPF.Record.LengthExceeds";
    public const string QueryFailed = "SPF.Query.Failed";
    public const string AllMultiple = "SPF.All.Multiple";
    public const string AllTrailingContent = "SPF.All.TrailingContent";
    public const string AllSoft = "SPF.All.Soft";
    public const string AllMissing = "SPF.All.Missing";
    public const string PtrUsed = "SPF.Ptr.Used";
    public const string ExistsUsed = "SPF.Exists.Used";

    // Positive/posture signals
    public const string Present = "SPF.Record.Present";
    public const string StartsV1 = "SPF.Record.StartsV1";
    public const string AllEnforced = "SPF.All.Enforced";
    public const string LookupsWithinLimit = "SPF.Lookups.WithinLimit";
    public const string IncludeChainValid = "SPF.Include.ChainValid";
    public const string FlattenedIpSetOptimized = "SPF.Flattened.IpSetOptimized";
}

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
}
